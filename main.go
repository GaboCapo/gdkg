package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== GitHub Deploy Key Generator ===")
	fmt.Println("1: Generate deploy key")
	fmt.Println("2: Remove Deploy Key")
	fmt.Println("3: Quit")

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Please select an option: ")
	if !scanner.Scan() {
		log.Fatal("Failed to read input:", scanner.Err())
	}
	choice := scanner.Text()

	switch choice {
	case "1":
		generateKey(scanner)
	case "2":
		revokeKey(scanner)
	default:
		fmt.Println("Task completed")
	}
}

func generateKey(scanner *bufio.Scanner) {
	// Repository name
	repo, err := askInput(scanner, "Repository-Name: ")
	if err != nil || repo == "" {
		log.Fatal("Invalid repository name")
	}
	if strings.ContainsAny(repo, `/\ `) {
		log.Fatal("Repository name contains invalid characters")
	}

	// Email for SSH comment
	email, err := askInput(scanner, "Email address for SSH comment (optional): ")
	if err != nil {
		log.Fatal("Failed to read email:", err)
	}
	if email == "" {
		email = "no-email@example.com"
	}

	// Target directory for keys
	home := userHomeDir()
	dir, err := askInput(scanner, fmt.Sprintf("Target dir for key files (default: %s/.ssh): ", home))
	if err != nil {
		log.Fatal("Failed to read target directory:", err)
	}
	if dir == "" {
		dir = filepath.Join(home, ".ssh")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal("Failed to create directory:", err)
	}

	// Key file paths
	privPath := filepath.Join(dir, repo+"_deploy-key")
	pubPath := privPath + ".pub"

	// Check if files already exist
	if fileExists(privPath) || fileExists(pubPath) {
		fmt.Printf("Warning: Key files already exist: %s and/or %s\n", privPath, pubPath)
		overwrite, err := askInput(scanner, "Do you want to overwrite them? (y/N): ")
		if err != nil || strings.ToLower(overwrite) != "y" {
			log.Fatal("Operation aborted by user")
		}
	}

	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Key generation failed:", err)
	}

	// Write private key in PEM format
	privPem := encodePrivateKeyToPEM(priv.Seed())
	if err := os.WriteFile(privPath, privPem, 0600); err != nil {
		log.Fatal("Failed to write private key:", err)
	}

	// Write public key in OpenSSH format
	sshPubKey := formatSSHPubKey(pub, email)
	if err := os.WriteFile(pubPath, []byte(sshPubKey), 0644); err != nil {
		log.Fatal("Failed to write public key:", err)
	}

	// Ask for GitHub username or organization
	githubUser, err := askInput(scanner, "GitHub username or organization: ")
	if err != nil || githubUser == "" {
		log.Fatal("Invalid GitHub username or organization")
	}

	// SSH config entry
	createConfig, err := askInput(scanner, "\nCreate matching SSH config entry? (Y/n): ")
	if err == nil && (createConfig == "" || strings.ToLower(createConfig) == "y") {
		alias := "github-" + repo
		fmt.Printf("Using SSH host alias: %s\n", alias)
		if err := addSSHConfigEntry(alias, privPath); err != nil {
			fmt.Println("Failed to update SSH config:", err)
		} else {
			fmt.Println("SSH config entry added.")
			fmt.Printf("Use this Git remote URL to use the deploy key:\n")
			fmt.Printf("git@%s:%s/%s.git\n", alias, githubUser, repo)
		}
	}

	// Git push commands
	fmt.Println("\n--- COPY BELOW TO PUSH USING YOUR DEPLOY KEY ---")
	fmt.Println("# Safe Mode (recommended)")
	fmt.Printf("GIT_SSH_COMMAND=\"ssh -i %s\" git push origin main\n", privPath)
	fmt.Println()
	fmt.Println("# Advanced Mode (for scripting, disables host key checking)")
	fmt.Printf("GIT_SSH_COMMAND=\"ssh -i %s -o StrictHostKeyChecking=no\" git push origin main\n", privPath)
}

func revokeKey(scanner *bufio.Scanner) {
	// Repository name
	repo, err := askInput(scanner, "Repository name to remove: ")
	if err != nil || repo == "" {
		log.Fatal("Invalid repository name")
	}

	// Key directory
	dir, err := askInput(scanner, "Directory of the key (press ENTER to use ~/.ssh): ")
	if err != nil {
		log.Fatal("Failed to read directory:", err)
	}
	if dir == "" {
		dir = filepath.Join(userHomeDir(), ".ssh")
	}

	// Key file paths
	privPath := filepath.Join(dir, repo+"_deploy-key")
	pubPath := privPath + ".pub"

	// Remove key files
	removeFileWithInfo(privPath, "private key")
	removeFileWithInfo(pubPath, "public key")

	// SSH config path
	configPath := filepath.Join(userHomeDir(), ".ssh", "config")
	if fileExists(configPath) {
		// Backup SSH config
		if err := backupFile(configPath); err != nil {
			fmt.Println("Warning: Failed to backup SSH config:", err)
		}
		// Remove SSH config entry
		alias := "github-" + repo
		if err := removeSSHConfigBlock(configPath, alias); err != nil {
			fmt.Println("Warning: Failed to remove SSH config entry:", err)
		} else {
			fmt.Println("SSH config entry removed.")
		}
	}
}

func askInput(scanner *bufio.Scanner, prompt string) (string, error) {
	fmt.Print(prompt)
	if !scanner.Scan() {
		return "", scanner.Err()
	}
	return strings.TrimSpace(scanner.Text()), nil
}

func removeFileWithInfo(path string, desc string) {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("%s file not found: %s\n", desc, path)
		} else {
			fmt.Printf("Error deleting %s file %s: %v\n", desc, path, err)
		}
	} else {
		fmt.Printf("%s file deleted: %s\n", desc, path)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("Cannot determine home directory:", err)
	}
	return home
}

func encodePrivateKeyToPEM(seed []byte) []byte {
	pkcs8prefix := []byte{
		0x30, 0x2c, // SEQUENCE, length 44
		0x02, 0x01, 0x00, // Version = 0
		0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier OID 1.3.101.112
		0x04, 0x20, // OCTET STRING (32 bytes)
	}
	data := append(pkcs8prefix, seed...)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})
}

func formatSSHPubKey(pub ed25519.PublicKey, comment string) string {
	var b bytes.Buffer
	b.WriteString("ssh-ed25519 ")
	b64 := base64.StdEncoding.EncodeToString(pub)
	b.WriteString(b64)
	if comment != "" {
		b.WriteByte(' ')
		b.WriteString(comment)
	}
	b.WriteByte('\n')
	return b.String()
}

func addSSHConfigEntry(alias, privPath string) error {
	configPath := filepath.Join(userHomeDir(), ".ssh", "config")
	content, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Contains(content, []byte("Host "+alias)) {
		return fmt.Errorf("SSH config entry for Host %s already exists", alias)
	}

	entry := fmt.Sprintf("\nHost %s\n\tHostName github.com\n\tUser git\n\tIdentityFile %s\n\tIdentitiesOnly yes\n", alias, privPath)
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}

func removeSSHConfigBlock(configPath, alias string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(content), "\n")
	var out []string
	inBlock := false
	hostLine := "Host " + alias
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Host ") && strings.Contains(trimmed, hostLine) {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.HasPrefix(trimmed, "Host ") && !strings.Contains(trimmed, hostLine) {
				inBlock = false
			} else {
				continue
			}
		}
		if !inBlock {
			out = append(out, line)
		}
	}
	return os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0600)
}

func backupFile(path string) error {
	timestamp := time.Now().Format("20060102T150405")
	backupPath := fmt.Sprintf("%s.backup.%s", path, timestamp)
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer output.Close()
	_, err = io.Copy(output, input)
	return err
}
