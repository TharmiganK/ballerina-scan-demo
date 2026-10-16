package demo.documents;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/documents")
public class DocumentController {

    private final String storageRoot;

    public DocumentController(@Value("${storage.root}") String storageRoot) {
        this.storageRoot = storageRoot;
    }

    @PutMapping("/{name}")
    public ResponseEntity<Void> upload(@PathVariable String name, @RequestBody byte[] content) throws IOException {
        // Vulnerable: ballerina/file:1 (CWE-377) - uploads are staged in the world-writable system temp directory.
        String stagingDir = System.getenv("TMP");
        Path stagedPath = Path.of(stagingDir + "/upload.bin");
        Files.createFile(stagedPath);
        Files.write(stagedPath, content);
        Files.copy(stagedPath, Path.of(storageRoot + name), StandardCopyOption.REPLACE_EXISTING);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/{name}")
    public byte[] download(@PathVariable String name) throws IOException {
        // Vulnerable: ballerina/io:1 (CWE-22) - the document name is joined into the path unchecked.
        byte[] content = Files.readAllBytes(Path.of(storageRoot + name));
        return content;
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<Void> delete(@PathVariable String name) throws IOException {
        // Vulnerable: ballerina/file:2 (CWE-22) - "../" in the name deletes files outside the store.
        Files.delete(Path.of(storageRoot + name));
        return ResponseEntity.noContent().build();
    }
}
