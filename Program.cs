using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Collections.Generic;
using MySqlConnector;
using System;
using System.IO;
using System.Text.Json;
using System.Diagnostics;
using System.Linq;

class TCPServer
{
    private static List<TcpClient> clients = new List<TcpClient>();
    private static readonly object clientLock = new object();
    private static string connectionString;
    private static readonly string configPath = "db_config.json";
    private static Dictionary<string, ChatRoom> chatRooms = new Dictionary<string, ChatRoom>();
    private static readonly object roomsLock = new object();
    private static Dictionary<string, DateTime> bannedUsers = new Dictionary<string, DateTime>();
    
    static void Main(string[] args)
    {
        // Setup database connection
        SetupDatabaseConfiguration();
        
        // Initialize database and create tables if they don't exist
        InitializeDatabase();
        
        // Initialize the general chat room
        lock (roomsLock)
        {
            chatRooms["general"] = new ChatRoom("general");
            Console.WriteLine("Default 'general' room created");
        }
        
        TcpListener server = new TcpListener(IPAddress.Any, 8443);
        server.Start();
        Console.WriteLine("Server started\nWaiting for connections...");

        while (true)
        {
            TcpClient client = server.AcceptTcpClient();
            Console.WriteLine($"New connection from {((IPEndPoint)client.Client.RemoteEndPoint).ToString()}");
            
            Thread clientThread = new Thread(new ParameterizedThreadStart(HandleClient));
            clientThread.Start(client);
        }
    }
    
    // Method to set up the database configuration
    static void SetupDatabaseConfiguration()
    {
        DbConfig config;
        
        // Check if config file exists
        if (File.Exists(configPath))
        {
            try
            {
                // Load existing configuration
                string jsonContent = File.ReadAllText(configPath);
                config = JsonSerializer.Deserialize<DbConfig>(jsonContent);
                Console.WriteLine("Database configuration loaded from file.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading configuration file: {ex.Message}");
                config = GetConfigFromUser();
                SaveConfigToFile(config);
            }
        }
        else
        {
            // Configuration file doesn't exist, get from user
            Console.WriteLine("No database configuration found. Please provide MariaDB connection details:");
            config = GetConfigFromUser();
            SaveConfigToFile(config);
        }
        
        // Build connection string
        connectionString = $"Server={config.Server};Port={config.Port};Database={config.Database};User ID={config.Username};Password={config.Password};";
        
        // Test connection
        if (TestDatabaseConnection())
        {
            Console.WriteLine("Database connection successful!");
        }
        else
        {
            Console.WriteLine("Failed to connect to the database. Please check your configuration.");
            Console.WriteLine("Would you like to reconfigure? (y/n)");
            string response = Console.ReadLine()?.ToLower();
            if (response == "y")
            {
                // Let user reconfigure without deleting file first
                config = GetConfigFromUser();
                SaveConfigToFile(config);
                // Test the new configuration
                connectionString = $"Server={config.Server};Port={config.Port};Database={config.Database};User ID={config.Username};Password={config.Password};";
                if (!TestDatabaseConnection())
                {
                    Console.WriteLine("Still unable to connect. Please check your MariaDB server.");
                    Environment.Exit(1); // Exit application
                }
            }
            else
            {
                Console.WriteLine("Cannot continue without database connection. Exiting.");
                Environment.Exit(1);
            }
        }
    }
    
    // Method to get configuration details from user
    static DbConfig GetConfigFromUser()
    {
        DbConfig config = new DbConfig();
        
        Console.Write("Server address (default: localhost): ");
        string server = Console.ReadLine();
        config.Server = string.IsNullOrWhiteSpace(server) ? "localhost" : server;
        
        Console.Write("Port (default: 3306): ");
        string portStr = Console.ReadLine();
        if (!int.TryParse(portStr, out int port) && !string.IsNullOrWhiteSpace(portStr))
        {
            port = 3306;
        }
        config.Port = string.IsNullOrWhiteSpace(portStr) ? 3306 : port;
        
        Console.Write("Database name: ");
        config.Database = Console.ReadLine();
        while (string.IsNullOrWhiteSpace(config.Database))
        {
            Console.Write("Database name cannot be empty. Please enter a database name: ");
            config.Database = Console.ReadLine();
        }
        
        Console.Write("Username: ");
        config.Username = Console.ReadLine();
        while (string.IsNullOrWhiteSpace(config.Username))
        {
            Console.Write("Username cannot be empty. Please enter a username: ");
            config.Username = Console.ReadLine();
        }
        
        Console.Write("Password: ");
        config.Password = GetPasswordFromConsole();
        
        return config;
    }
    
    // Method to get password without displaying it
    static string GetPasswordFromConsole()
    {
        string password = "";
        ConsoleKeyInfo key;
        
        do
        {
            key = Console.ReadKey(true);
            
            // Ignore any control key like Ctrl or Alt
            if (!char.IsControl(key.KeyChar))
            {
                password += key.KeyChar;
                Console.Write("*");
            }
            // Handle backspace
            else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password = password.Substring(0, password.Length - 1);
                Console.Write("\b \b");
            }
        } while (key.Key != ConsoleKey.Enter);
        
        Console.WriteLine();
        return password;
    }
    
    // Save configuration to file
    static void SaveConfigToFile(DbConfig config)
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string jsonString = JsonSerializer.Serialize(config, options);
            File.WriteAllText(configPath, jsonString);
            Console.WriteLine($"Configuration saved to {configPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving configuration: {ex.Message}");
        }
    }
    
    // Test the database connection
    static bool TestDatabaseConnection()
    {
        try
        {
            using (var connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                return true;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Connection test failed: {ex.Message}");
            return false;
        }
    }
    
    // Add this method to create the database table
    static void InitializeDatabase()
    {
        try
        {
            using (var connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                
                // Create users table if it doesn't exist
                string createTableSql = @"
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) NOT NULL UNIQUE,
                        password_hash VARCHAR(64) NOT NULL,
                        salt VARCHAR(64) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )";
                    
                using (var command = new MySqlCommand(createTableSql, connection))
                {
                    command.ExecuteNonQuery();
                }
                
                // Check if admin user exists, if not create it
                string checkAdminSql = "SELECT COUNT(*) FROM users WHERE username = 'admin'";
                using (var command = new MySqlCommand(checkAdminSql, connection))
                {
                    long adminCount = (long)command.ExecuteScalar();
                    if (adminCount == 0)
                    {
                        // Create default admin user
                        string salt = GenerateSalt();
                        string passwordHash = HashPassword("senha123", salt);
                        
                        string insertAdminSql = @"
                            INSERT INTO users (username, password_hash, salt)
                            VALUES (@username, @passwordHash, @salt)";
                            
                        using (var insertCommand = new MySqlCommand(insertAdminSql, connection))
                        {
                            insertCommand.Parameters.AddWithValue("@username", "admin");
                            insertCommand.Parameters.AddWithValue("@passwordHash", passwordHash);
                            insertCommand.Parameters.AddWithValue("@salt", salt);
                            insertCommand.ExecuteNonQuery();
                        }
                        
                        Console.WriteLine("Default admin user created");
                    }
                }
                
                Console.WriteLine("Database initialization completed");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Database initialization error: {ex.Message}");
        }
    }

    static void HandleClient(object clientObj)
    {
        TcpClient tcpClient = (TcpClient)clientObj;
        NetworkStream stream = tcpClient.GetStream();
        string username = null;
        bool isAuthenticated = false;
        ClientInfo clientInfo = null;

        try
        {
            // Send welcome message with authentication instructions
            string welcomeMsg = "Welcome to TCP server!\r\nPlease authenticate using:\r\n/login username:password\r\n/register username:password";
            byte[] welcomeBytes = Encoding.ASCII.GetBytes(welcomeMsg);
            stream.Write(welcomeBytes, 0, welcomeBytes.Length);

            // Buffer for reading data
            byte[] buffer = new byte[1024];
            int bytesRead;

            // Authentication loop
            while (!isAuthenticated)
            {
                bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) return; // Client disconnected

                string message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                Console.WriteLine($"Auth attempt from {((IPEndPoint)tcpClient.Client.RemoteEndPoint).ToString()}: {message}");

                if (message.StartsWith("/login "))
                {
                    string[] parts = message.Substring(7).Trim().Split(':');
                    if (parts.Length == 2)
                    {
                        string user = parts[0];
                        string password = parts[1];

                        // Add this check in authentication
                        lock (bannedUsers)
                        {
                            if (bannedUsers.TryGetValue(user.ToLower(), out DateTime banExpiry))
                            {
                                if (DateTime.Now < banExpiry)
                                {
                                    TimeSpan remaining = banExpiry - DateTime.Now;
                                    string response = $"Your account is banned. Ban expires in {(int)remaining.TotalMinutes} minutes.";
                                    byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                                    stream.Write(responseBytes, 0, responseBytes.Length);
                                    return;
                                }
                                else
                                {
                                    // Ban expired, remove from list
                                    bannedUsers.Remove(user.ToLower());
                                }
                            }
                        }
                        
                        if (ValidateUserFromDatabase(user, password))
                        {
                            isAuthenticated = true;
                            username = user;
                            
                            // Add to general room
                            lock (roomsLock)
                            {
                                ChatRoom generalRoom = chatRooms["general"];
                                clientInfo = new ClientInfo(tcpClient, stream, username, generalRoom);
                                generalRoom.AddClient(clientInfo);
                            }
                            
                            string response = "Login successful! You have joined the 'general' room. You can now chat.";
                            byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseBytes, 0, responseBytes.Length);
                        }
                        else
                        {
                            string response = "Authentication failed. Try again.";
                            byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseBytes, 0, responseBytes.Length);
                        }
                    }
                }
                else if (message.StartsWith("/register "))
                {
                    string[] parts = message.Substring(10).Trim().Split(':');
                    if (parts.Length == 2)
                    {
                        string user = parts[0];
                        string password = parts[1];
                        
                        if (RegisterUserToDatabase(user, password))
                        {
                            isAuthenticated = true;
                            username = user;
                            
                            // Add to general room
                            lock (roomsLock)
                            {
                                ChatRoom generalRoom = chatRooms["general"];
                                clientInfo = new ClientInfo(tcpClient, stream, username, generalRoom);
                                generalRoom.AddClient(clientInfo);
                            }
                            
                            string response = "Registration successful! You have joined the 'general' room. You can now chat.";
                            byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseBytes, 0, responseBytes.Length);
                        }
                        else
                        {
                            string response = "Registration failed. Username may already exist.";
                            byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseBytes, 0, responseBytes.Length);
                        }
                    }
                }
                else
                {
                    string response = "Invalid command. Use '/login username:password' or '/register username:password'";
                    byte[] responseBytes = Encoding.ASCII.GetBytes(response);
                    stream.Write(responseBytes, 0, responseBytes.Length);
                }
            }

            // Add to client list only after authentication
            lock (clientLock)
            {
                clients.Add(tcpClient);
            }
            Console.WriteLine($"Client {username} authenticated and joined general room. Total clients: {clients.Count}");
            
            // Announce new user to the room
            clientInfo.CurrentRoom.BroadcastMessage("Server", $"{username} has joined the room.");

            // Regular communication after authentication
            while (true)
            {
                bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) break; // Client disconnected

                string message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                Console.WriteLine($"Received from {username} in room '{clientInfo.CurrentRoom.Name}': {message}");

                // Add this check before processing messages
                const int MAX_MESSAGES_PER_MINUTE = 30;
                const int RATE_LIMIT_RESET_SECONDS = 60;

                if ((DateTime.Now - clientInfo.LastMessageTime).TotalSeconds > RATE_LIMIT_RESET_SECONDS)
                {
                    clientInfo.MessageCount = 0;
                    clientInfo.LastMessageTime = DateTime.Now;
                }
                else
                {
                    clientInfo.MessageCount++;
                    if (clientInfo.MessageCount > MAX_MESSAGES_PER_MINUTE)
                    {
                        SendResponse(stream, "Rate limit exceeded. Please slow down.");
                        continue; // Skip processing this message
                    }
                }

                // Log the message
                LogMessage(clientInfo.Username, clientInfo.CurrentRoom.Name, message);

                // Check if message is a command
                if (message.StartsWith("/"))
                {
                    string[] commandParts = message.Trim().Split(' ', 2);
                    string command = commandParts[0].ToLower();
                    string parameter = commandParts.Length > 1 ? commandParts[1] : string.Empty;

                    switch (command)
                    {
                        case "/help":
                            SendHelpMessage(stream, username == "admin");
                            break;
                            
                        case "/quit":
                        case "/logout":
                            string logoutResponse = "Logging out. Goodbye!";
                            byte[] logoutBytes = Encoding.ASCII.GetBytes(logoutResponse);
                            stream.Write(logoutBytes, 0, logoutBytes.Length);
                            return; // This will exit the method and trigger the finally block
                            
                        case "/create-room":
                            if (!string.IsNullOrWhiteSpace(parameter))
                                CreateRoom(parameter, clientInfo, stream);
                            else
                                SendResponse(stream, "Usage: /create-room roomName");
                            break;
                            
                        case "/join-room":
                            if (!string.IsNullOrWhiteSpace(parameter))
                                JoinRoom(parameter, clientInfo, stream);
                            else
                                SendResponse(stream, "Usage: /join-room roomName");
                            break;
                            
                        case "/list-rooms":
                            ListRooms(stream);
                            break;
                            
                        case "/dm":
                            if (string.IsNullOrWhiteSpace(parameter))
                            {
                                SendResponse(stream, "Usage: /dm username message");
                                break;
                            }
                            
                            string[] dmParts = parameter.Split(' ', 2);
                            if (dmParts.Length < 2 || string.IsNullOrWhiteSpace(dmParts[0]) || string.IsNullOrWhiteSpace(dmParts[1]))
                            {
                                SendResponse(stream, "Usage: /dm username message");
                                break;
                            }
                            
                            SendDirectMessage(dmParts[0], dmParts[1], clientInfo, stream);
                            break;

                        case "/users":
                            ListUsers(stream, username == "admin");
                            break;
                            
                        // Admin-only commands
                        case "/kick":
                            if (username != "admin")
                            {
                                SendResponse(stream, "Permission denied: Admin access required");
                                break;
                            }
                            
                            if (string.IsNullOrWhiteSpace(parameter))
                            {
                                SendResponse(stream, "Usage: /kick username");
                                break;
                            }
                            
                            KickUser(parameter, stream);
                            break;
                            
                        case "/delete-room":
                            if (username != "admin")
                            {
                                SendResponse(stream, "Permission denied: Admin access required");
                                break;
                            }
                            
                            if (string.IsNullOrWhiteSpace(parameter))
                            {
                                SendResponse(stream, "Usage: /delete-room roomName");
                                break;
                            }
                            
                            DeleteRoom(parameter, stream);
                            break;

                        case "/broadcast":
                            if (username != "admin")
                            {
                                SendResponse(stream, "Permission denied: Admin access required");
                                break;
                            }
                            
                            if (string.IsNullOrWhiteSpace(parameter))
                            {
                                SendResponse(stream, "Usage: /broadcast message");
                                break;
                            }
                            
                            BroadcastGlobal(parameter, stream);
                            break;

                        case "/server-status":
                            if (username != "admin")
                            {
                                SendResponse(stream, "Permission denied: Admin access required");
                                break;
                            }
                            
                            SendServerStatus(stream);
                            break;

                        case "/ban":
                            if (username != "admin")
                            {
                                SendResponse(stream, "Permission denied: Admin access required");
                                break;
                            }
                            
                            string[] banParams = parameter.Split(' ', 2);
                            if (banParams.Length < 2)
                            {
                                SendResponse(stream, "Usage: /ban username minutes");
                                break;
                            }
                            
                            string banUser = banParams[0];
                            if (!int.TryParse(banParams[1], out int minutes) || minutes <= 0)
                            {
                                SendResponse(stream, "Ban duration must be a positive number of minutes");
                                break;
                            }
                            
                            BanUser(banUser, minutes, stream);
                            break;

                        default:
                            SendResponse(stream, "Unknown command. Type /help for available commands.");
                            break;
                    }
                }
                else
                {
                    // Broadcast the message to everyone in the room
                    clientInfo.CurrentRoom.BroadcastMessage(username, message);
                    
                    // Echo back to sender with room prefix
                    string echoResponse = $"[{clientInfo.CurrentRoom.Name}] You: {message}";
                    byte[] echoBytes = Encoding.ASCII.GetBytes(echoResponse);
                    stream.Write(echoBytes, 0, echoBytes.Length);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            // Remove from room
            if (clientInfo != null)
            {
                lock (roomsLock)
                {
                    if (clientInfo.CurrentRoom != null)
                    {
                        clientInfo.CurrentRoom.RemoveClient(clientInfo);
                        clientInfo.CurrentRoom.BroadcastMessage("Server", $"{username} has left the room.");
                    }
                }
            }
            
            // Remove from client list
            lock (clientLock)
            {
                clients.Remove(tcpClient);
            }
            Console.WriteLine($"Client {username ?? "unknown"} disconnected. Total clients: {clients.Count}");
            tcpClient.Close();
        }
    }

    // Generate a random salt for each user
    static string GenerateSalt()
    {
        byte[] saltBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }
        return Convert.ToBase64String(saltBytes);
    }

    // Update the password hashing to include salt
    static string HashPassword(string password, string salt)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + salt));
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }
    }

    // Replace ValidateUser with database version
    static bool ValidateUserFromDatabase(string username, string password)
    {
        try
        {
            using (var connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                string sql = "SELECT password_hash, salt FROM users WHERE username = @username";
                
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@username", username);
                    
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string storedHash = reader.GetString("password_hash");
                            string salt = reader.GetString("salt");
                            string computedHash = HashPassword(password, salt);
                            
                            return storedHash == computedHash;
                        }
                    }
                }
            }
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Database error in ValidateUserFromDatabase: {ex.Message}");
            return false;
        }
    }

    // Replace RegisterUser with database version
    static bool RegisterUserToDatabase(string username, string password)
    {
        try
        {
            using (var connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                
                // Check if username already exists
                string checkSql = "SELECT COUNT(*) FROM users WHERE username = @username";
                using (var checkCommand = new MySqlCommand(checkSql, connection))
                {
                    checkCommand.Parameters.AddWithValue("@username", username);
                    long userCount = (long)checkCommand.ExecuteScalar();
                    if (userCount > 0)
                    {
                        return false;
                    }
                }
                
                // Username doesn't exist, create new user
                string salt = GenerateSalt();
                string passwordHash = HashPassword(password, salt);
                
                string insertSql = @"
                    INSERT INTO users (username, password_hash, salt)
                    VALUES (@username, @passwordHash, @salt)";
                    
                using (var command = new MySqlCommand(insertSql, connection))
                {
                    command.Parameters.AddWithValue("@username", username);
                    command.Parameters.AddWithValue("@passwordHash", passwordHash);
                    command.Parameters.AddWithValue("@salt", salt);
                    
                    int rowsAffected = command.ExecuteNonQuery();
                    return rowsAffected > 0;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Database error in RegisterUserToDatabase: {ex.Message}");
            return false;
        }
    }

    // Helper method to send response to client
    static void SendResponse(NetworkStream stream, string message)
    {
        byte[] responseBytes = Encoding.ASCII.GetBytes(message);
        stream.Write(responseBytes, 0, responseBytes.Length);
    }

    // Send help message based on user role
    static void SendHelpMessage(NetworkStream stream, bool isAdmin)
    {
        StringBuilder help = new StringBuilder();
        help.AppendLine("Available commands:");
        help.AppendLine("/help - Show this help message");
        help.AppendLine("/logout or /quit - Disconnect from the server");
        help.AppendLine("/create-room [roomName] - Create a new chat room");
        help.AppendLine("/join-room [roomName] - Join an existing chat room");
        help.AppendLine("/list-rooms - List all available chat rooms");
        help.AppendLine("/dm [username] [message] - Send a direct message to a user");
        help.AppendLine("/users - List users in your current room");
        
        if (isAdmin)
        {
            help.AppendLine("\nAdmin commands:");
            help.AppendLine("/kick [username] - Kick a user from the server");
            help.AppendLine("/delete-room [roomName] - Delete a chat room");
            help.AppendLine("/broadcast [message] - Broadcast message to all users");
            help.AppendLine("/server-status - Show server statistics");
            help.AppendLine("/ban [username] [minutes] - Ban a user for a specified number of minutes");
        }
        
        SendResponse(stream, help.ToString());
    }

    // Create a new chat room
    static void CreateRoom(string roomName, ClientInfo clientInfo, NetworkStream stream)
    {
        static void CreateRoom(string roomName, ClientInfo clientInfo, NetworkStream stream)
        {
            if (string.IsNullOrWhiteSpace(roomName) || roomName.Contains(" "))
            {
                SendResponse(stream, "Room name cannot be empty or contain spaces.");
                return;
            }
            
            // ...rest of the method...
        }        if (string.IsNullOrWhiteSpace(roomName) || roomName.Contains(" "))
        {
            SendResponse(stream, "Room name cannot be empty or contain spaces.");
            return;
        }

        lock (roomsLock)
        {
            if (chatRooms.ContainsKey(roomName.ToLower()))
            {
                SendResponse(stream, $"Room '{roomName}' already exists.");
                return;
            }

            chatRooms[roomName.ToLower()] = new ChatRoom(roomName);
            SendResponse(stream, $"Room '{roomName}' created successfully.");
            Console.WriteLine($"Room '{roomName}' created by {clientInfo.Username}");
        }
    }

    // Join an existing chat room
    static void JoinRoom(string roomName, ClientInfo clientInfo, NetworkStream stream)
    {
        lock (roomsLock)
        {
            if (!chatRooms.TryGetValue(roomName.ToLower(), out ChatRoom targetRoom))
            {
                SendResponse(stream, $"Room '{roomName}' does not exist.");
                return;
            }

            if (clientInfo.CurrentRoom != null)
            {
                // Announce departure from current room
                clientInfo.CurrentRoom.BroadcastMessage("Server", $"{clientInfo.Username} has left the room.");
                clientInfo.CurrentRoom.RemoveClient(clientInfo);
            }

            // Add to new room
            targetRoom.AddClient(clientInfo);
            clientInfo.CurrentRoom = targetRoom;

            SendResponse(stream, $"You have joined the room '{roomName}'.");
            targetRoom.BroadcastMessage("Server", $"{clientInfo.Username} has joined the room.");
        }
    }

    // List all available chat rooms
    static void ListRooms(NetworkStream stream)
    {
        StringBuilder roomList = new StringBuilder();
        roomList.AppendLine("Available rooms:");

        lock (roomsLock)
        {
            foreach (var room in chatRooms.Values)
            {
                roomList.AppendLine($"- {room.Name} ({room.Clients.Count} users)");
            }
        }

        SendResponse(stream, roomList.ToString());
    }

    // Send a direct message to another user
    static void SendDirectMessage(string targetUsername, string message, ClientInfo sender, NetworkStream stream)
    {
        ClientInfo recipient = null;
        
        // Find the recipient across all rooms
        lock (roomsLock)
        {
            foreach (var room in chatRooms.Values)
            {
                recipient = room.Clients.FirstOrDefault(c => c.Username.Equals(targetUsername, StringComparison.OrdinalIgnoreCase));
                if (recipient != null) break;
            }
        }

        if (recipient == null)
        {
            SendResponse(stream, $"User '{targetUsername}' not found or not connected.");
            return;
        }

        // Send message to recipient
        try
        {
            byte[] dmBytes = Encoding.ASCII.GetBytes($"[DM from {sender.Username}]: {message}");
            recipient.Stream.Write(dmBytes, 0, dmBytes.Length);
            
            // Confirmation to sender
            SendResponse(stream, $"[DM to {targetUsername}]: {message}");
            Console.WriteLine($"DM from {sender.Username} to {targetUsername}");
        }
        catch (Exception ex)
        {
            SendResponse(stream, $"Failed to send message to {targetUsername}: {ex.Message}");
        }
    }

    // List users in the current room or all users if admin
    static void ListUsers(NetworkStream stream, bool isAdmin)
    {
        StringBuilder userList = new StringBuilder();

        if (isAdmin)
        {
            userList.AppendLine("All connected users (admin view):");
            
            lock (roomsLock)
            {
                foreach (var room in chatRooms.Values)
                {
                    userList.AppendLine($"\nRoom: {room.Name}");
                    foreach (var client in room.Clients)
                    {
                        userList.AppendLine($"- {client.Username} ({((IPEndPoint)client.Client.Client.RemoteEndPoint).ToString()})");
                    }
                }
            }
        }
        else
        {
            // For regular users, just show users in their current room
            ClientInfo clientInfo = null;
            
            lock (clientLock)
            {
                foreach (var room in chatRooms.Values)
                {
                    clientInfo = room.Clients.FirstOrDefault(c => c.Stream == stream);
                    if (clientInfo != null) break;
                }
            }
            
            if (clientInfo != null && clientInfo.CurrentRoom != null)
            {
                userList.AppendLine($"Users in room '{clientInfo.CurrentRoom.Name}':");
                foreach (var client in clientInfo.CurrentRoom.Clients)
                {
                    userList.AppendLine($"- {client.Username}");
                }
            }
            else
            {
                userList.AppendLine("Error: Could not determine your current room.");
            }
        }
        
        SendResponse(stream, userList.ToString());
    }

    // Admin command to kick a user
    static void KickUser(string username, NetworkStream stream)
    {
        ClientInfo targetClient = null;
        
        // Find the user across all rooms
        lock (roomsLock)
        {
            foreach (var room in chatRooms.Values)
            {
                targetClient = room.Clients.FirstOrDefault(c => 
                    c.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
                if (targetClient != null) break;
            }
        }

        if (targetClient == null)
        {
            SendResponse(stream, $"User '{username}' not found.");
            return;
        }

        if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
        {
            SendResponse(stream, "Cannot kick the admin user.");
            return;
        }

        try
        {
            // Notify the user they are being kicked
            SendResponse(targetClient.Stream, "You have been kicked from the server by an administrator.");
            
            // Force disconnect by closing the client
            targetClient.Client.Close();
            
            SendResponse(stream, $"User '{username}' has been kicked.");
            Console.WriteLine($"User '{username}' has been kicked by admin.");
        }
        catch (Exception ex)
        {
            SendResponse(stream, $"Error kicking user: {ex.Message}");
        }
    }

    // Admin command to delete a room
    static void DeleteRoom(string roomName, NetworkStream stream)
    {
        if (roomName.Equals("general", StringComparison.OrdinalIgnoreCase))
        {
            SendResponse(stream, "Cannot delete the 'general' room.");
            return;
        }

        lock (roomsLock)
        {
            if (!chatRooms.TryGetValue(roomName.ToLower(), out ChatRoom room))
            {
                SendResponse(stream, $"Room '{roomName}' does not exist.");
                return;
            }

            // Move all users to general room
            ChatRoom generalRoom = chatRooms["general"];
            foreach (var client in room.Clients.ToList())
            {
                // Notify user
                SendResponse(client.Stream, $"Room '{roomName}' has been deleted by an administrator. You've been moved to 'general'.");
                
                // Move client
                room.RemoveClient(client);
                generalRoom.AddClient(client);
                client.CurrentRoom = generalRoom;
            }

            // Remove room
            chatRooms.Remove(roomName.ToLower());
            SendResponse(stream, $"Room '{roomName}' deleted successfully and all users moved to 'general'.");
            Console.WriteLine($"Room '{roomName}' deleted by admin");
        }
    }

    // Admin command to broadcast to all users
    static void BroadcastGlobal(string message, NetworkStream stream)
    {
        lock (roomsLock)
        {
            foreach (var room in chatRooms.Values)
            {
                foreach (var client in room.Clients.ToList())
                {
                    try
                    {
                        byte[] broadcastBytes = Encoding.ASCII.GetBytes($"[ADMIN BROADCAST]: {message}");
                        client.Stream.Write(broadcastBytes, 0, broadcastBytes.Length);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error broadcasting to {client.Username}: {ex.Message}");
                    }
                }
            }
        }

        SendResponse(stream, $"Broadcast sent: {message}");
        Console.WriteLine($"Admin broadcast: {message}");
    }

    // Admin command to get server status
    static void SendServerStatus(NetworkStream stream)
    {
        int totalUsers = 0;
        StringBuilder status = new StringBuilder();
        status.AppendLine("==== SERVER STATUS ====");
        
        lock (roomsLock)
        {
            status.AppendLine($"Total rooms: {chatRooms.Count}");
            
            foreach (var room in chatRooms)
            {
                totalUsers += room.Value.Clients.Count;
            }
            
            status.AppendLine($"Total connected users: {totalUsers}");
            status.AppendLine("\nRoom details:");
            
            foreach (var room in chatRooms)
            {
                status.AppendLine($"- {room.Key}: {room.Value.Clients.Count} users");
            }
        }
        
        status.AppendLine("\nServer uptime: " + (DateTime.Now - Process.GetCurrentProcess().StartTime).ToString(@"dd\.hh\:mm\:ss"));
        status.AppendLine("Memory usage: " + (Process.GetCurrentProcess().WorkingSet64 / (1024 * 1024)) + " MB");
        
        SendResponse(stream, status.ToString());
    }

    // Add this method
    static void LogMessage(string username, string roomName, string message)
    {
        try
        {
            string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {username} | {roomName} | {message}";
            File.AppendAllText("chat_log.txt", logEntry + Environment.NewLine);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error logging message: {ex.Message}");
        }
    }

    // Implement the BanUser method
    static void BanUser(string username, int minutes, NetworkStream stream)
    {
        if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
        {
            SendResponse(stream, "Cannot ban the admin user.");
            return;
        }

        // Add to banned users list
        lock (bannedUsers)
        {
            bannedUsers[username.ToLower()] = DateTime.Now.AddMinutes(minutes);
        }
        
        // Kick the user if they're online
        KickUser(username, stream);
        
        SendResponse(stream, $"User '{username}' has been banned for {minutes} minutes.");
        Console.WriteLine($"User '{username}' has been banned for {minutes} minutes by admin.");
    }
}

// Class to store database configuration
class DbConfig
{
    public string Server { get; set; } = "localhost";
    public int Port { get; set; } = 3306;
    public string Database { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

// Add this class after the DbConfig class
class ChatRoom
{
    public string Name { get; private set; }
    public List<ClientInfo> Clients { get; private set; } = new List<ClientInfo>();

    public ChatRoom(string name)
    {
        Name = name;
    }

    public void AddClient(ClientInfo client)
    {
        if (!Clients.Contains(client))
        {
            Clients.Add(client);
        }
    }

    public void RemoveClient(ClientInfo client)
    {
        Clients.Remove(client);
    }

    public void BroadcastMessage(string sender, string message)
    {
        foreach (var client in Clients.ToList()) // Create a copy to avoid modification issues
        {
            try
            {
                if (client.Username != sender) // Don't send back to sender
                {
                    byte[] messageBytes = Encoding.ASCII.GetBytes($"[{Name}] {sender}: {message}");
                    client.Stream.Write(messageBytes, 0, messageBytes.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error broadcasting to {client.Username}: {ex.Message}");
                // The client will be removed in the HandleClient method's finally block
            }
        }
    }
}

class ClientInfo
{
    public TcpClient Client { get; set; }
    public NetworkStream Stream { get; set; }
    public string Username { get; set; }
    public ChatRoom CurrentRoom { get; set; }
    public DateTime LastMessageTime { get; set; } = DateTime.MinValue;
    public int MessageCount { get; set; } = 0;

    public ClientInfo(TcpClient client, NetworkStream stream, string username, ChatRoom room)
    {
        Client = client;
        Stream = stream;
        Username = username;
        CurrentRoom = room;
    }
}
