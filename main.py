#!/usr/bin/env python3
"""
MCP Filesystem Server - Secure file operations with OpenAPI endpoints

Based on the Open WebUI reference implementation with security enhancements.
"""

import os
import pathlib
import json
from typing import List, Union, Optional, Dict, Any
from pathlib import Path
import hashlib
import mimetypes
from datetime import datetime

from fastapi import FastAPI, HTTPException, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Configuration
ALLOWED_PATHS = os.getenv("FILESYSTEM_ALLOWED_PATHS", "/workspace,/tmp").split(",")
ALLOWED_PATHS = [Path(path.strip()).resolve() for path in ALLOWED_PATHS]

app = FastAPI(
    title="MCP Filesystem Server",
    version="1.0.0",
    description="Secure filesystem operations with configurable access restrictions",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class ReadFileRequest(BaseModel):
    path: str = Field(..., description="Path to the file to read")
    encoding: str = Field("utf-8", description="File encoding")
    max_size: int = Field(1024*1024, description="Maximum file size in bytes")

class WriteFileRequest(BaseModel):
    path: str = Field(..., description="Path to the file to write")
    content: str = Field(..., description="Content to write to the file")
    encoding: str = Field("utf-8", description="File encoding")
    create_dirs: bool = Field(True, description="Create parent directories if they don't exist")

class ListDirectoryRequest(BaseModel):
    path: str = Field(..., description="Path to the directory to list")
    recursive: bool = Field(False, description="List directories recursively")
    show_hidden: bool = Field(False, description="Show hidden files")

class DeletePathRequest(BaseModel):
    path: str = Field(..., description="Path to delete")
    recursive: bool = Field(False, description="Delete directories recursively")

class FileInfo(BaseModel):
    name: str
    path: str
    type: str  # 'file' or 'directory'
    size: Optional[int] = None
    modified: Optional[str] = None
    permissions: Optional[str] = None
    mime_type: Optional[str] = None

class DirectoryListing(BaseModel):
    path: str
    items: List[FileInfo]
    total_items: int

class SuccessResponse(BaseModel):
    success: bool = True
    message: str

def normalize_path(path: str) -> Path:
    """Normalize and validate file path"""
    try:
        resolved_path = Path(path).resolve()
        
        # Check if path is within allowed directories
        for allowed_path in ALLOWED_PATHS:
            try:
                resolved_path.relative_to(allowed_path)
                return resolved_path
            except ValueError:
                continue
        
        raise HTTPException(
            status_code=403,
            detail=f"Access denied. Path must be within: {', '.join(str(p) for p in ALLOWED_PATHS)}"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid path: {str(e)}")

def get_file_info(path: Path) -> FileInfo:
    """Get file information"""
    stat = path.stat()
    
    return FileInfo(
        name=path.name,
        path=str(path),
        type="directory" if path.is_dir() else "file",
        size=stat.st_size if path.is_file() else None,
        modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
        permissions=oct(stat.st_mode)[-3:],
        mime_type=mimetypes.guess_type(str(path))[0] if path.is_file() else None
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "mcp-filesystem"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "MCP Filesystem Server", "version": "1.0.0"}

@app.get("/allowed-paths")
async def get_allowed_paths():
    """Get list of allowed paths"""
    return {"allowed_paths": [str(p) for p in ALLOWED_PATHS]}

@app.post("/read-file")
async def read_file(request: ReadFileRequest = Body(...)):
    """Read a file"""
    file_path = normalize_path(request.path)
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    if not file_path.is_file():
        raise HTTPException(status_code=400, detail="Path is not a file")
    
    if file_path.stat().st_size > request.max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size: {request.max_size} bytes"
        )
    
    try:
        content = file_path.read_text(encoding=request.encoding)
        return {
            "content": content,
            "file_info": get_file_info(file_path),
            "encoding": request.encoding
        }
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot decode file with encoding: {request.encoding}"
        )

@app.post("/write-file")
async def write_file(request: WriteFileRequest = Body(...)):
    """Write a file"""
    file_path = normalize_path(request.path)
    
    if request.create_dirs:
        file_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        file_path.write_text(request.content, encoding=request.encoding)
        return {
            "success": True,
            "message": f"File written successfully: {file_path}",
            "file_info": get_file_info(file_path)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing file: {str(e)}")

@app.post("/list-directory")
async def list_directory(request: ListDirectoryRequest = Body(...)):
    """List directory contents"""
    dir_path = normalize_path(request.path)
    
    if not dir_path.exists():
        raise HTTPException(status_code=404, detail="Directory not found")
    
    if not dir_path.is_dir():
        raise HTTPException(status_code=400, detail="Path is not a directory")
    
    items = []
    
    def add_items(path: Path, level: int = 0):
        try:
            for item in path.iterdir():
                if not request.show_hidden and item.name.startswith('.'):
                    continue
                
                items.append(get_file_info(item))
                
                if request.recursive and item.is_dir() and level < 10:  # Limit recursion depth
                    add_items(item, level + 1)
        except PermissionError:
            pass  # Skip directories we can't read
    
    add_items(dir_path)
    
    return DirectoryListing(
        path=str(dir_path),
        items=items,
        total_items=len(items)
    )

@app.post("/delete-path")
async def delete_path(request: DeletePathRequest = Body(...)):
    """Delete a file or directory"""
    path = normalize_path(request.path)
    
    if not path.exists():
        raise HTTPException(status_code=404, detail="Path not found")
    
    try:
        if path.is_file():
            path.unlink()
            return SuccessResponse(message=f"File deleted: {path}")
        elif path.is_dir():
            if request.recursive:
                import shutil
                shutil.rmtree(path)
                return SuccessResponse(message=f"Directory deleted recursively: {path}")
            else:
                path.rmdir()
                return SuccessResponse(message=f"Directory deleted: {path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting path: {str(e)}")

@app.post("/create-directory")
async def create_directory(path: str = Body(..., embed=True)):
    """Create a directory"""
    dir_path = normalize_path(path)
    
    try:
        dir_path.mkdir(parents=True, exist_ok=True)
        return {
            "success": True,
            "message": f"Directory created: {dir_path}",
            "directory_info": get_file_info(dir_path)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating directory: {str(e)}")

@app.post("/file-info")
async def get_file_info_endpoint(path: str = Body(..., embed=True)):
    """Get file or directory information"""
    file_path = normalize_path(path)
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Path not found")
    
    return get_file_info(file_path)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)