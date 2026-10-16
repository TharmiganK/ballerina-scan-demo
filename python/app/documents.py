import os
import shutil

from flask import Blueprint, request

documents = Blueprint("documents", __name__, url_prefix="/documents")

STORAGE_ROOT = os.environ.get("STORAGE_ROOT", "./documents/")


@documents.put("/<name>")
def upload(name: str):
    # Vulnerable: ballerina/file:1 (CWE-377) - uploads are staged in the world-writable system temp directory.
    staged_path = os.environ["TMP"] + "/upload.bin"
    with open(staged_path, "wb") as staged:
        staged.write(request.get_data())
    shutil.copyfile(staged_path, STORAGE_ROOT + name)
    return "", 201


@documents.get("/<name>")
def download(name: str):
    # Vulnerable: ballerina/io:1 (CWE-22) - the document name is joined into the path unchecked.
    with open(STORAGE_ROOT + name, "rb") as document:
        content = document.read()
    return content


@documents.delete("/<name>")
def delete(name: str):
    # Vulnerable: ballerina/file:2 (CWE-22) - "../" in the name deletes files outside the store.
    os.remove(STORAGE_ROOT + name)
    return "", 204
