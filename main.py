import os
import json
import subprocess
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Response, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Annotated, Optional
import logging
from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/extension/token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

users_db = {
    os.getenv("WEBDAV_LOGIN"): {
        "username": os.getenv("WEBDAV_LOGIN"),
        "password": os.getenv("WEBDAV_PASSWORD"),
    }
}

def get_user(username: str):
    return users_db.get(username)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if user["password"] != password:
        return False
    return user

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = get_user(username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

router = APIRouter(prefix="/extension", tags=["Extension Tools"])

def _run_local_command(command: str, cwd: str = "/") -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
            cwd=cwd
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command execution failed: {e.stderr.strip()}")
        raise HTTPException(status_code=500, detail=f"Command execution failed: {e.stderr.strip()}")
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        raise HTTPException(status_code=500, detail=f"Error executing command: {e}")

@router.post("/token", operation_id="extension__get_token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/execute_command", operation_id="extension__execute_command")
async def execute_command(command: str, _current_user: Annotated[dict, Depends(get_current_user)]) -> str:
    """Executes a local shell command on the NAS server."""
    return _run_local_command(command)

@router.post("/search_text", operation_id="extension__search_text")
async def search_text(current_user: Annotated[dict, Depends(get_current_user)], path: str = Query("/"), query: str = "") -> str:
    """Searches for files containing a specific text query on the NAS server using 'grep'."""
    if not query:
        raise HTTPException(status_code=400, detail="Search query cannot be empty.")
    
    escaped_query = query.replace("'", "'\\''")
    command = f"grep -rl '{escaped_query}' {path}"
    
    try:
        output = _run_local_command(command, path)
        found_files = output.split('\n') if output else []
        return json.dumps([f for f in found_files if f], ensure_ascii=False)
    except HTTPException as e:
        if "Command execution failed" in e.detail and "No such file or directory" in e.detail:
            raise HTTPException(status_code=404, detail=f"Path '{path}' not found on NAS server.")
        if "Command execution failed" in e.detail and "returned non-zero exit status 1" in e.detail:
            return json.dumps([], ensure_ascii=False)
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during local search_text operation: {e}")

@router.post("/find_files", operation_id="extension__find_files")
async def find_files(current_user: Annotated[dict, Depends(get_current_user)], path: str = Query("/"), pattern: str = "") -> str:
    """Finds files matching a pattern on the NAS server using 'find'."""
    if not pattern:
        raise HTTPException(status_code=400, detail="File pattern cannot be empty.")
    
    command = f"find {path} -name '{pattern}'"
    
    try:
        output = _run_local_command(command, path)
        found_files = output.split('\n') if output else []
        return json.dumps([f for f in found_files if f], ensure_ascii=False)
    except HTTPException as e:
        if "Command execution failed" in e.detail and "No such file or directory" in e.detail:
            raise HTTPException(status_code=404, detail=f"Path '{path}' not found on NAS server.")
        if "Command execution failed" in e.detail and "returned non-zero exit status 1" in e.detail:
            return json.dumps([], ensure_ascii=False)
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during local find_files operation: {e}")


def _get_gitignore_patterns(repo_path: str) -> PathSpec:
    """Fetches and parses .gitignore content from the local file system."""
    gitignore_path = os.path.join(repo_path, ".gitignore")
    try:
        with open(gitignore_path, 'r') as f:
            return PathSpec.from_lines(GitWildMatchPattern, f.readlines())
    except FileNotFoundError:
        return PathSpec.from_lines(GitWildMatchPattern, [])
    except Exception:
        return PathSpec.from_lines(GitWildMatchPattern, [])

def _get_git_tree_info(repo_path: str, gitignore_spec: PathSpec) -> list[dict]:
    """Gets Git tracked files/dirs and their last modified dates, respecting .gitignore."""
    command = f"git -C {repo_path} ls-tree -r HEAD --name-only"
    tracked_paths_output = _run_local_command(command, repo_path)
    tracked_paths = tracked_paths_output.strip().splitlines()

    filtered_paths = []
    for p in tracked_paths:
        if not gitignore_spec.match_file(p):
            filtered_paths.append(p)
    
    file_info = []
    for p in filtered_paths:
        date_command = f'git -C {repo_path} log -1 --format="%cd" --date=format:"%Y-%m-%d %H:%M:%S" -- "{p}"'
        last_modified = _run_local_command(date_command, repo_path)
        
        is_dir_command = f"git -C {repo_path} ls-tree HEAD \"{p}\""
        is_dir_result = _run_local_command(is_dir_command, repo_path)
        is_dir = "tree" in is_dir_result

        file_info.append({
            "path": p,
            "last_modified": last_modified,
            "is_dir": is_dir
        })
    return file_info

def _format_tree_output(file_info: list[dict], terminal_width: int = 80) -> str:
    """Formats the file information into a tree-like string with right-aligned dates."""
    tree_lines = []
    
    tree = {}
    for item in file_info:
        parts = item["path"].split('/')
        current_level = tree
        for i, part in enumerate(parts):
            if part not in current_level:
                current_level[part] = {}
            if i == len(parts) - 1:
                current_level[part] = item
            current_level = current_level[part]
    
    def _build_lines(node, prefix="", is_last_sibling=False):
        keys = list(node.keys())
        for i, key in enumerate(sorted(keys)):
            item = node[key]
            is_last_item = (i == len(keys) - 1)
            
            indent_prefix = "└── " if is_last_item else "├── "
            new_prefix = prefix + ("    " if is_last_sibling else "│   ")
            
            display_name = key
            last_modified_str = item.get("last_modified", "")
            
            line_content = f"{prefix}{indent_prefix}{display_name}"
            
            if isinstance(item, dict) and "is_dir" in item and not item["is_dir"]:
                available_space = terminal_width - len(line_content)
                if available_space > 0:
                    padding = " " * max(1, available_space - len(last_modified_str)) 
                    line_content += f"{padding}{last_modified_str}"

            tree_lines.append(line_content)
            
            if isinstance(item, dict) and "is_dir" in item and item["is_dir"]:
                _build_lines(item, new_prefix, is_last_item)
            elif isinstance(item, dict) and item and "path" not in item:
                 _build_lines(item, new_prefix, is_last_item)


    _build_lines(tree)
    return "\n".join(tree_lines)

@router.post("/directory_tree", operation_id="extension__directory_tree")
async def directory_tree(
    current_user: Annotated[dict, Depends(get_current_user)],
    path: str = Query("/"),
    terminal_width: int = 80
) -> str:
    """
    Generates a directory tree for a Git repository on the NAS server,
    excluding .gitignore'd files and displaying last modified dates.
    """
    try:
        git_check_command = f"git -C {path} rev-parse --is-inside-work-tree"
        git_check_result = _run_local_command(git_check_command, path)
        if "true" not in git_check_result:
            raise HTTPException(status_code=400, detail=f"Path '{path}' is not a Git repository or git command failed.")

        gitignore_spec = _get_gitignore_patterns(path)
        file_info = _get_git_tree_info(path, gitignore_spec)
        
        return _format_tree_output(file_info, terminal_width)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating Git directory tree: {e}")

app = FastAPI(
    title="NAS Extension Server", 
    version="1.0.0",
    docs_url="/extension/docs",  # Swagger UI 문서 경로를 지정
    redoc_url="/extension/redoc", # ReDoc 문서 경로를 지정
    openapi_url="/extension/openapi.json" # OpenAPI 스키마 경로를 지정
)
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
