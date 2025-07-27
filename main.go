package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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

	// Generate Ed25519 key pair using ssh-keygen
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-C", email, "-f", privPath, "-N", "")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal("Failed to generate key pair with ssh-keygen:", err)
	}

	// Read and display public key for GitHub
	pubKeyBytes, err := os.ReadFile(pubPath)
	if err != nil {
		log.Fatal("Failed to read public key:", err)
	}
	fmt.Println("\n--- COPY THE PUBLIC KEY BELOW TO GITHUB ---")
	fmt.Printf("%s", string(pubKeyBytes))
	fmt.Println("Add this key to your GitHub repository under Settings > Deploy keys")

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

			// Automatically add the private key to ssh-agent
			if err := addKeyToSSHAgent(privPath); err != nil {
				fmt.Printf("Warning: Failed to add key to ssh-agent: %v\n", err)
				fmt.Println("You may need to manually run: ssh-add", privPath)
			} else {
				fmt.Println("Private key added to ssh-agent.")
			}
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

	// Diagnose: Print SSH_AUTH_SOCK
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		fmt.Println("Warning: SSH_AUTH_SOCK is not set, ssh-agent may not be running.")
	} else {
		fmt.Printf("Using SSH_AUTH_SOCK: %s\n", sshAuthSock)
	}

	// Get the fingerprint of the key if the file exists
	var fingerprint string
	if fileExists(privPath) {
		fingerprint, err = getKeyFingerprint(privPath)
		if err != nil {
			fmt.Printf("Warning: Could not get fingerprint for %s: %v\n", privPath, err)
		}
	}

	// Remove key from ssh-agent
	if fingerprint != "" && isKeyInSSHAgent(fingerprint) {
		if err := removeKeyFromSSHAgent(privPath); err != nil {
			fmt.Printf("Warning: Failed to remove key from ssh-agent: %v\n", err)
			fmt.Println("You may need to manually remove all keys using: ssh-add -D")
		} else {
			fmt.Println("Private key removed from ssh-agent.")
		}
	} else {
		fmt.Println("Key not found in ssh-agent or no valid fingerprint, skipping removal.")
		if !fileExists(privPath) {
			fmt.Println("Note: Private key file does not exist, cannot verify fingerprint.")
		}
	}

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

func addKeyToSSHAgent(keyPath string) error {
	// Check if ssh-agent is running
	cmd := exec.Command("ssh-add", "-l")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-agent is not running or inaccessible: %v", err)
	}

	// Add the key to ssh-agent
	cmd = exec.Command("ssh-add", keyPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add key to ssh-agent: %v", err)
	}
	return nil
}

func getKeyFingerprint(keyPath string) (string, error) {
	cmd := exec.Command("ssh-keygen", "-l", "-f", keyPath)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get fingerprint: %v", err)
	}

	// Parse the fingerprint from the output, e.g.:
	// 256 SHA256:GXfx:FizweV/CU2MsaYgH0U20kpLGZxg/2M4mXVEu3L7u+c no-email@example.com (ED25519)
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", fmt.Errorf("no fingerprint found in output")
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid fingerprint format")
	}
	return parts[1], nil // Return the fingerprint (e.g., SHA256:GXfx:FizweV/...)
}

func isKeyInSSHAgent(fingerprint string) bool {
	if fingerprint == "" {
		return false
	}

	cmd := exec.Command("ssh-add", "-l")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Warning: Could not list ssh-agent keys: %v\n", err)
		return false // SSH-Agent nicht erreichbar oder leer
	}

	// Check if the fingerprint is in the output of ssh-add -l
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, fingerprint) {
			return true
		}
	}
	return false
}

func removeKeyFromSSHAgent(keyPath string) error {
	// Check if ssh-agent is running
	cmd := exec.Command("ssh-add", "-l")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-agent is not running or inaccessible: %v", err)
	}

	// Try to remove the key from ssh-agent
	cmd = exec.Command("ssh-add", "-d", keyPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove key from ssh-agent: %v", err)
	}
	return nil
}
