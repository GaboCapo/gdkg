package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	fmt.Println("=== GitHub Deploy Key Generator ===")
	fmt.Println("1: Generate deploy key")
	fmt.Println("2: Remove Deploy Key")
	fmt.Println("3: Quit")

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Please select an option: ")
	scanner.Scan()
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
	fmt.Print("Repository-Name: ")
	scanner.Scan()
	repo := scanner.Text()

	fmt.Print("Email address for SSH comment: ")
	scanner.Scan()
	email := scanner.Text()

	home := userHomeDir()
	fmt.Printf("Target dir for key files (default: %s/.ssh): ", home)
	scanner.Scan()
	dir := scanner.Text()
	if dir == "" {
		dir = filepath.Join(home, ".ssh")
	}

	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatal("Failed to create directory:", err)
	}

	privPath := filepath.Join(dir, repo+"_deploy-key")
	pubPath := privPath + ".pub"

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(privPath, encodePEM(priv.Seed()), 0600)
	if err != nil {
		log.Fatal(err)
	}

	sshPubKey := formatSSHPubKey(pub, email)
	err = os.WriteFile(pubPath, []byte(sshPubKey), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n--- PUBLIC KEY (Add to GitHub Repository Settings) ---")
	fmt.Println(sshPubKey)

	// SSH config entry
	fmt.Print("\nCreate matching SSH config entry? (Y/n): ")
	scanner.Scan()
	ans := strings.TrimSpace(scanner.Text())
	if ans == "" || strings.ToLower(ans) == "y" {
		err = addSSHConfigEntry(dir, repo, privPath)
		if err != nil {
			fmt.Println("Failed to update SSH config:", err)
		} else {
			fmt.Println("SSH config entry added.")
			fmt.Printf("Use this Git remote URL to use the deploy key:\n")
			fmt.Printf("git@github.com-%s:user/%s.git\n", repo, repo)
		}
	}

	// Push-Befehle (EN)
	fmt.Println("\n--- COPY BELOW TO PUSH USING YOUR DEPLOY KEY ---")
	fmt.Println("# Safe Mode (Recommended)")
	fmt.Printf("GIT_SSH_COMMAND=\"ssh -i %s\" git push origin main\n", privPath)

	fmt.Println()
	fmt.Println("# Advanced Mode (for scripting, skips host key check)")
	fmt.Printf("GIT_SSH_COMMAND=\"ssh -i %s -o StrictHostKeyChecking=no\" git push origin main\n", privPath)

	fmt.Printf("\n# Note: These commands are only valid for pushing to the GitHub repository named '%s'\n", repo)
}

func revokeKey(scanner *bufio.Scanner) {
	fmt.Print("Repository name to remove: ")
	scanner.Scan()
	repo := strings.TrimSpace(scanner.Text())

	fmt.Print("Directory of the key (press ENTER to use ~/.ssh): ")
	scanner.Scan()
	dir := scanner.Text()
	if dir == "" {
		dir = filepath.Join(userHomeDir(), ".ssh")
	}

	privPath := filepath.Join(dir, repo+"_deploy-key")
	pubPath := privPath + ".pub"

	os.Remove(privPath)
	os.Remove(pubPath)
	fmt.Println("Deploy key files removed.")

	configPath := filepath.Join(userHomeDir(), ".ssh", "config")
	if _, err := os.Stat(configPath); err == nil {
		removeSSHConfigBlock(configPath, repo)
	}
}

func addSSHConfigEntry(dir, repo, privPath string) error {
	configPath := filepath.Join(userHomeDir(), ".ssh", "config")

	content := ""
	if data, err := os.ReadFile(configPath); err == nil {
		content = string(data)
	}

	if strings.Contains(content, "Host github.com-"+repo) {
		return fmt.Errorf("SSH config entry for repo '%s' already exists", repo)
	}

	entry := fmt.Sprintf(`
Host github.com-%s
  HostName github.com
  User git
  IdentityFile %s
  IdentitiesOnly yes
`, repo, privPath)

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(entry)
	return err
}

func removeSSHConfigBlock(configPath, repo string) {
	input, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Println("Warning: Failed to read SSH config:", err)
		return
	}

	lines := strings.Split(string(input), "\n")
	var output []string
	skip := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Host ") && strings.Contains(line, repo) {
			skip = true
			continue
		}
		if skip {
			if strings.HasPrefix(line, "Host ") {
				skip = false
			}
		}
		if !skip {
			output = append(output, line)
		}
	}

	err = os.WriteFile(configPath, []byte(strings.Join(output, "\n")), 0600)
	if err != nil {
		fmt.Println("Warning: Failed to update SSH config:", err)
		return
	}

	fmt.Println("SSH config block removed (if existed).")
}

func encodePEM(data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	})
}

func formatSSHPubKey(pub ed25519.PublicKey, comment string) string {
	key := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
	key = append(key, encodeLengthAndData(pub)...)
	encoded := base64.StdEncoding.EncodeToString(key)
	return fmt.Sprintf("ssh-ed25519 %s %s", encoded, comment)
}

func encodeLengthAndData(data []byte) []byte {
	l := len(data)
	return append([]byte{
		byte(l >> 24),
		byte(l >> 16),
		byte(l >> 8),
		byte(l),
	}, data...)
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERPROFILE")
	}
	return os.Getenv("HOME")
}

