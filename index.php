<?php
session_start();

// --- SECURITY WARNING ---
// The following implementation of storing user data in a plain text file (data.txt)
// and using 3DES for password encryption is HIGHLY INSECURE and NOT recommended
// for production environments. This is for demonstration purposes ONLY, as per
// the user's specific request.
// For real-world applications, always use a robust database (e.g., MySQL, PostgreSQL)
// and strong, one-way password hashing (e.g., password_hash() with PASSWORD_BCRYPT).
// --- END SECURITY WARNING ---

// 3DES Configuration (Insecure to hardcode in production environment)
// The key MUST be 24 bytes (characters) for DES-EDE3 (Triple DES).
// The IV (Initialization Vector) MUST be 8 bytes (characters) for DES-EDE3-CBC mode.
$key = 'ThisIsAStrong24ByteKeyFor3DES!'; // Example 24-byte key
$iv = '8ByteIV!'; // Example 8-byte IV

/**
 * Encrypts data using 3DES (Triple DES) in CBC mode.
 *
 * @param string $data The data to encrypt.
 * @param string $key The encryption key (24 bytes).
 * @param string $iv The initialization vector (8 bytes).
 * @return string The base64-encoded encrypted data.
 */
function encrypt_3des($data, $key, $iv) {
    // openssl_encrypt returns false on failure, handle it gracefully
    $encrypted = openssl_encrypt($data, 'DES-EDE3-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($encrypted === false) {
        error_log("3DES Encryption failed: " . openssl_error_string());
        return ''; // Return empty string on failure
    }
    return base64_encode($encrypted); // Base64 encode for safe storage/transmission
}

/**
 * Decrypts data using 3DES (Triple DES) in CBC mode.
 *
 * @param string $data The base64-encoded data to decrypt.
 * @param string $key The encryption key (24 bytes).
 * @param string $iv The initialization vector (8 bytes).
 * @return string The decrypted data.
 */
function decrypt_3des($data, $key, $iv) {
    // Base64 decode the data first
    $decodedData = base64_decode($data);
    if ($decodedData === false) {
        error_log("3DES Decryption failed: Invalid base64 data.");
        return ''; // Return empty string on failure
    }
    // openssl_decrypt returns false on failure, handle it gracefully
    $decrypted = openssl_decrypt($decodedData, 'DES-EDE3-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        error_log("3DES Decryption failed: " . openssl_error_string());
        return ''; // Return empty string on failure
    }
    return $decrypted;
}

// Initialize message variable for user feedback
$message = '';
// Check if user is already logged in
$loggedInUser = $_SESSION['username'] ?? null;

// Handle POST requests (Login, Register, Send Message)
if (isset($_POST['action'])) {
    if ($_POST['action'] === 'register') {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        // Basic input validation
        if (empty($username) || empty($email) || empty($password)) {
            $message = '<span class="error">All fields are required for registration.</span>';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = '<span class="error">Invalid email format.</span>';
        } else {
            // Read existing users from data.txt
            $users = file_exists('data.txt') ? file('data.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            $userExists = false;
            foreach ($users as $userLine) {
                // Split each line into username, email, encrypted password
                list($u, $e, $p) = explode('|', $userLine);
                if ($u === $username || $e === $email) {
                    $userExists = true;
                    break;
                }
            }

            if ($userExists) {
                $message = '<span class="error">Username or Email already exists.</span>';
            } else {
                // Encrypt the password using 3DES
                $encryptedPassword = encrypt_3des($password, $key, $iv);
                // Append new user data to data.txt
                file_put_contents('data.txt', "$username|$email|$encryptedPassword\n", FILE_APPEND);
                $message = '<span class="success">Registration successful! Please log in.</span>';
            }
        }
    } elseif ($_POST['action'] === 'login') {
        $identifier = trim($_POST['identifier'] ?? ''); // Can be username or email
        $password = $_POST['password'] ?? '';

        // Basic input validation
        if (empty($identifier) || empty($password)) {
            $message = '<span class="error">Both identifier and password are required for login.</span>';
        } else {
            // Read existing users from data.txt
            $users = file_exists('data.txt') ? file('data.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            $loggedIn = false;
            foreach ($users as $userLine) {
                // Ensure the line has enough parts before exploding
                $parts = explode('|', $userLine);
                if (count($parts) < 3) {
                    continue; // Skip malformed lines
                }
                list($u, $e, $p_encrypted) = $parts;

                // Decrypt the stored password for comparison (this is why hashing is preferred)
                $p_decrypted = decrypt_3des($p_encrypted, $key, $iv);

                // Check if identifier matches username or email, and if decrypted password matches
                if (($u === $identifier || $e === $identifier) && $p_decrypted === $password) {
                    $_SESSION['username'] = $u; // Store username in session
                    $loggedInUser = $u; // Update local variable
                    $loggedIn = true;
                    $message = '<span class="success">Login successful!</span>';
                    break;
                }
            }

            if (!$loggedIn) {
                $message = '<span class="error">Invalid credentials.</span>';
            }
        }
    }
} elseif (isset($_GET['logout'])) {
    // Handle logout request
    session_destroy(); // Destroy all session data
    $loggedInUser = null; // Clear logged-in user variable
    $message = '<span class="success">You have been logged out.</span>';
    header('Location: index.php'); // Redirect to clear GET parameter and refresh page
    exit();
}

// --- Messenger Logic (only if user is logged in) ---
if ($loggedInUser && isset($_POST['send_message'])) {
    $messageContent = trim($_POST['message_content'] ?? '');
    if (!empty($messageContent)) {
        $timestamp = date('Y-m-d H:i:s'); // Get current timestamp
        // Format the chat message
        $chatMessage = "[$timestamp] $loggedInUser: $messageContent\n";
        // Append message to messages.txt
        file_put_contents('messages.txt', $chatMessage, FILE_APPEND);
    }
}

// Read all existing messages for display (regardless of login state, but displayed only if logged in)
$chatMessages = file_exists('messages.txt') ? file('messages.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali Messenger</title>
    <!-- Google Fonts for a terminal-like appearance -->
    <link href="https://fonts.googleapis.com/css2?family=Anonymous+Pro&family=Fira+Code&display=swap" rel="stylesheet">
    <style>
        /* Define CSS variables for easy theme customization */
        :root {
            --bg-color: #1a1a1a; /* Dark background */
            --text-color: #00ff00; /* Kali green text */
            --border-color: #008000; /* Darker green border */
            --input-bg: #333; /* Input field background */
            --button-bg: #008000; /* Button background */
            --button-hover-bg: #00b300; /* Button hover background */
            --error-color: #ff0000; /* Red for errors */
            --success-color: #00cc00; /* Brighter green for success */
        }

        body {
            font-family: 'Fira Code', 'Anonymous Pro', monospace; /* Terminal-like font */
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: flex-start; /* Align to top for better scrolling on content-heavy pages */
            min-height: 100vh; /* Full viewport height */
            box-sizing: border-box;
            flex-direction: column; /* Allows vertical stacking of elements */
        }

        .container {
            background-color: #0a0a0a; /* Even darker background for the main container */
            border: 1px solid var(--border-color);
            box-shadow: 0 0 15px var(--border-color); /* Green glowing shadow */
            padding: 30px;
            border-radius: 8px; /* Slightly rounded corners */
            width: 100%;
            max-width: 600px; /* Max width for readability on larger screens */
            box-sizing: border-box;
            margin-bottom: 20px; /* Space between sections if multiple containers */
        }

        h1, h2 {
            color: var(--text-color);
            text-align: center;
            margin-bottom: 25px;
            text-shadow: 0 0 5px var(--text-color); /* Subtle text glow */
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 15px; /* Space between form elements */
        }

        label {
            margin-bottom: 5px;
            display: block;
            color: var(--text-color);
        }

        input[type="text"],
        input[type="email"],
        input[type="password"],
        textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border-color);
            background-color: var(--input-bg);
            color: var(--text-color);
            border-radius: 5px;
            box-sizing: border-box; /* Include padding/border in element's total width/height */
            font-family: 'Fira Code', 'Anonymous Pro', monospace;
            font-size: 1em;
            outline: none; /* Remove default outline on focus */
            transition: border-color 0.3s, box-shadow 0.3s; /* Smooth transition for focus effect */
        }

        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="password"]:focus,
        textarea:focus {
            border-color: var(--button-hover-bg);
            box-shadow: 0 0 8px var(--button-hover-bg); /* Glowing effect on focus */
        }

        button {
            background-color: var(--button-bg);
            color: var(--bg-color); /* Dark text on green button */
            padding: 12px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-family: 'Fira Code', 'Anonymous Pro', monospace;
            font-size: 1.1em;
            transition: background-color 0.3s, box-shadow 0.3s;
            text-transform: uppercase; /* Uppercase button text */
            font-weight: bold;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); /* Subtle button shadow */
        }

        button:hover {
            background-color: var(--button-hover-bg);
            box-shadow: 0 0 10px var(--button-hover-bg), 0 6px 8px rgba(0, 0, 0, 0.4); /* Enhanced glow on hover */
        }

        .message {
            text-align: center;
            margin-top: 20px;
            padding: 10px;
            border-radius: 5px;
            font-weight: bold;
        }

        .error {
            color: var(--error-color);
            border: 1px solid var(--error-color);
            background-color: rgba(255, 0, 0, 0.1); /* Light red background for errors */
            display: block;
            padding: 10px;
            margin-top: 15px;
            border-radius: 5px;
        }

        .success {
            color: var(--success-color);
            border: 1px solid var(--success-color);
            background-color: rgba(0, 255, 0, 0.1); /* Light green background for success */
            display: block;
            padding: 10px;
            margin-top: 15px;
            border-radius: 5px;
        }

        .toggle-form-btn {
            background: none;
            border: none;
            color: var(--text-color);
            text-decoration: underline;
            cursor: pointer;
            font-size: 0.9em;
            margin-top: 15px;
            text-align: center;
            display: block;
            width: 100%; /* Make button take full width */
            padding: 5px; /* Add some padding */
            transition: color 0.3s;
        }

        .toggle-form-btn:hover {
            color: var(--button-hover-bg);
        }

        .messenger-area {
            height: 300px; /* Fixed height for chat display */
            overflow-y: scroll; /* Enable vertical scrolling */
            border: 1px solid var(--border-color);
            background-color: #050505; /* Very dark background for chat messages */
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            word-wrap: break-word; /* Break long words */
            white-space: pre-wrap; /* Preserve whitespace and line breaks */
            line-height: 1.6; /* Improve readability of chat messages */
            font-size: 0.95em;
        }

        .chat-message {
            margin-bottom: 8px;
            line-height: 1.4;
        }

        .chat-message:last-child {
            margin-bottom: 0; /* No margin after the last message */
        }

        .logout-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: var(--text-color);
            text-decoration: none;
            padding: 10px 15px;
            background-color: #444; /* Darker grey background for logout button */
            border-radius: 5px;
            transition: background-color 0.3s;
            font-weight: bold;
        }

        .logout-link:hover {
            background-color: #666; /* Lighter grey on hover */
        }

        /* Responsive adjustments for smaller screens */
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            .container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($loggedInUser): ?>
            <!-- Display Messenger Interface if user is logged in -->
            <h1>Welcome, <span style="color: var(--success-color);"><?php echo htmlspecialchars($loggedInUser); ?></span>!</h1>
            <h2>Kali Messenger</h2>
            <div class="messenger-area" id="chat-box">
                <?php
                // Display existing chat messages
                foreach ($chatMessages as $msg): ?>
                    <div class="chat-message"><?php echo htmlspecialchars($msg); ?></div>
                <?php endforeach; ?>
            </div>
            <form method="POST" action="index.php">
                <textarea name="message_content" rows="4" placeholder="Type your message here..."></textarea>
                <button type="submit" name="send_message">Send Message</button>
            </form>
            <a href="index.php?logout=true" class="logout-link">Logout</a>
        <?php else: ?>
            <!-- Display Login/Register Forms if user is not logged in -->
            <h1>Kali Login / Register</h1>
            <?php if ($message): ?>
                <div class="message"><?php echo $message; ?></div>
            <?php endif; ?>

            <div id="login-form">
                <h2>Login</h2>
                <form method="POST" action="index.php">
                    <label for="login-identifier">Username or Email:</label>
                    <input type="text" id="login-identifier" name="identifier" required>
                    <label for="login-password">Password:</label>
                    <input type="password" id="login-password" name="password" required>
                    <button type="submit" name="action" value="login">Login</button>
                </form>
                <button class="toggle-form-btn" onclick="showRegisterForm()">Don't have an account? Register here.</button>
            </div>

            <div id="register-form" style="display: none;">
                <h2>Register</h2>
                <form method="POST" action="index.php">
                    <label for="reg-username">Username:</label>
                    <input type="text" id="reg-username" name="username" required>
                    <label for="reg-email">Email:</label>
                    <input type="email" id="reg-email" name="email" required>
                    <label for="reg-password">Password:</label>
                    <input type="password" id="reg-password" name="password" required>
                    <button type="submit" name="action" value="register">Register</button>
                </form>
                <button class="toggle-form-btn" onclick="showLoginForm()">Already have an account? Login here.</button>
            </div>
        <?php endif; ?>
    </div>

    <script>
        /**
         * Shows the registration form and hides the login form.
         */
        function showRegisterForm() {
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('register-form').style.display = 'block';
        }

        /**
         * Shows the login form and hides the registration form.
         */
        function showLoginForm() {
            document.getElementById('register-form').style.display = 'none';
            document.getElementById('login-form').style.display = 'block';
        }

        // Automatically scroll the chat box to the bottom when the page loads
        // This ensures the latest messages are always visible.
        const chatBox = document.getElementById('chat-box');
        if (chatBox) {
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    </script>
</body>
</html>
