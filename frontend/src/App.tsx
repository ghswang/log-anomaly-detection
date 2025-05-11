import React, { useState, useEffect } from 'react'; // Import React hooks for state management and side effects
import './App.css' // Import the CSS for styling

// Define the structure of a single log entry
interface LogEntry {
  id: number; // Unique identifier for the log entry
  time_received: string; // Timestamp when the log was received
  src_ip: string; // Source IP address
  action: string; // Action taken (e.g., ALLOW, DENY)
  status_code: number; // HTTP status code
  is_anomaly: boolean; // Flag indicating if the entry is an anomaly
  confidence_score: number; // Confidence score of the anomaly detection
  anomaly_reason?: string; // Optional reason for why the entry is an anomaly
}

const App: React.FC = () => { // Define the main functional component
  const [username, setUsername] = useState<string>(''); // State for username
  const [password, setPassword] = useState<string>(''); // State for password
  const [loggedIn, setLoggedIn] = useState<boolean>(false); // State to track if the user is logged in
  const [message, setMessage] = useState<string>(''); // State to hold login message
  const [logs, setLogs] = useState<LogEntry[]>([]); // State to hold fetched or uploaded log entries
  const [file, setFile] = useState<File | null>(null); // State to store the selected file
  const [uploading, setUploading] = useState(false); // State to show upload status
  const [error, setError] = useState<string | null>(null); // State to capture and display errors

  // Function to handle login form submission
  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault(); // Prevent the default form submission

    // Basic Authentication header encoding
    const authHeader = 'Basic ' + btoa(`${username}:${password}`); // Base64 encode the username and password

    try {
      const response = await fetch('http://localhost:5000/login', {
        method: 'GET',
        headers: {
          'Authorization': authHeader, // Add the Authorization header for Basic Auth
        },
      });

      if (response.ok) {
        const data = await response.json(); // Parse JSON response
        setMessage(data.message); // Set the message state to the welcome message
        setLoggedIn(true); // Set the loggedIn state to true
        setError(null); // Clear any previous errors
        localStorage.setItem('authHeader', authHeader); // Store credentials in localStorage for reuse (ONLY USABLE FOR DEV/TESTING)
      } else {
        throw new Error('Login failed'); // If response is not OK, throw an error
      }
    } catch (error: any) {
      setError(error.message); // Set error message if login fails
      setLoggedIn(false); // Ensure loggedIn state is false on error
    }
  };

  // Function triggered when user selects a file
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) { // Check if files were selected
      const selectedFile = event.target.files[0];
      const fileExtension = selectedFile.name.split('.').pop()?.toLowerCase(); // Get the file extension

      // Check if the file is either .txt or .log
      if (fileExtension !== 'txt' && fileExtension !== 'log') {
        setError('Only .txt and .log files are supported.');
        setFile(null); // Clear file state if invalid file type
      } else {
        setFile(selectedFile); // Set the selected file if it's valid
        setError(null); // Clear any previous error
      }
    }
  };

  // Function to upload selected log file to the Flask backend
  const handleFileUpload = async () => {
    if (!file) { // If no file is selected, alert the user
      alert('Please select a file before uploading.');
      return;
    }

    const authHeader = localStorage.getItem('authHeader'); // Check if user has already logged in
    if (!authHeader) { // If the user has not logged in
      alert('You must be logged in to upload.');
      return;
   } // NOTE: ONLY USABLE FOR DEV/TESTING

    setUploading(true); // Show uploading status
    setError(null); // Reset previous errors

    const formData = new FormData(); // Create a new FormData object
    formData.append('file', file); // Append the selected file to the form data

    try {
      // Send the file to the backend server using POST
      const response = await fetch('http://localhost:5000/upload', {
        method: 'POST',
        headers: { // NOTE: ONLY USABLE FOR DEV/TESTING
          Authorization: authHeader, // Add the Authorization header for Basic Auth
        },
        body: formData,
      });

      if (!response.ok) { // Check if response is unsuccessful
        throw new Error('File upload failed');
      }
      await fetchLogs(); // Fetch the logs

    } catch (error: any) {
      setError(error.message); // Set error state if something went wrong
    } finally {
      setUploading(false); // Reset uploading state regardless of outcome
    }
  };

  // Function to fetch logs from backend
  const fetchLogs = async () => {
    // If the user has already logged in, proceed as usual
    const authHeader = localStorage.getItem('authHeader'); // NOTE: ONLY USABLE FOR DEV/TESTING
    if (!authHeader) return; // Otherwise, don't fetch the logs
    
    try {
      const response = await fetch('http://localhost:5000/logs', { // Fetch logs from backend
        headers: { // NOTE: ONLY USABLE FOR DEV/TESTING
          Authorization: authHeader, // Add the Authorization header for Basic Auth
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch logs');
      }

      const data = await response.json(); // Parse JSON response
      setLogs(data); // Update the logs state
    } catch (error: any) {
      setError(error.message); // Set error if fetch fails
    }
  };

  // Function to clear all logs using DELETE request
  const handleClearLogs = async () => {
    if (!window.confirm('Are you sure you want to delete all logs?')) return; // Ask for confirmation

    const authHeader = localStorage.getItem('authHeader'); // Check if user has already logged in
    if (!authHeader) { // If the user has not logged in
      alert('You must be logged in to upload.');
      return;
    } // NOTE: ONLY USABLE FOR DEV/TESTING

    try {
      const response = await fetch('http://localhost:5000/logs', {
        method: 'DELETE', // Send DELETE request to backend
        headers: {
          'Authorization': authHeader, // Add the Authorization header for Basic Auth
        },
      });

      if (!response.ok) {
        throw new Error('Failed to delete logs'); // Handle failure
      }

      setLogs([]); // Clear logs in frontend state
    } catch (error: any) {
      setError(error.message); // Show error if deletion fails
    }
  };

  // useEffect runs once on component mount to fetch logs initially
  useEffect(() => {
    const savedAuth = localStorage.getItem('authHeader'); // NOTE: ONLY USABLE FOR DEV/TESTING
    if (savedAuth) { // If the user already logged in before
      setLoggedIn(true); // Pretend the user is still logged in
      fetchLogs(); // Fetch logs if logged in
    }
  }, []);

  return (
    <div className="App">
      <h1>Log Parser Frontend</h1>

      {/* Show error messages if any */}
      {error && <div className="error">Error: {error}</div>}

      {/* Login form */}
      {!loggedIn ? (
        <div>
          <h2>Login</h2>
          <form onSubmit={handleLogin}>
            <div>
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)} // Update username state
                required
              />
            </div>
            <div>
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)} // Update password state
                required
              />
            </div>
            <button type="submit">Login</button>
          </form>
        </div>
      ) : (
        <div>
          <h2>{message}</h2> {/* Display welcome message if logged in */}

      {/* File upload section (with type restriction) */}
      <div>
        <input type="file" accept=".txt,.log" onChange={handleFileChange} /> {/* File input field (only accepts .txt and .log files) */}
        <button onClick={handleFileUpload} disabled={uploading}> {/* Upload button */}
          {uploading ? 'Uploading...' : 'Upload Log File'} {/* Dynamic label */}
        </button>
        <button onClick={handleClearLogs} style={{ marginLeft: '1rem' }}> {/* Button to delete all logs */}
          Clear All Logs
        </button>
      </div>

      <h2>Log Entries</h2> {/* Section heading */}

      {logs.length > 0 ? ( // If logs are available, render the table
        <div className="log-table-container"> {/* Container to enable horizontal scrolling if needed */}
          <table className="log-table"> {/* Main styled log table */}
            <thead> {/* Table header section */}
              <tr> {/* Table header row */}
                <th>Time Received</th> {/* Column for time log was received */}
                <th>Source IP</th>     {/* Column for source IP address */}
                <th>Action</th>        {/* Column for action taken (e.g., ALLOWED, BLOCKED) */}
                <th>Status</th>        {/* Column for HTTP status code */}
                <th>Anomaly</th>       {/* Column to indicate if it's an anomaly */}
                <th>Confidence</th>    {/* Column showing anomaly detection confidence score */}
                <th>Reason</th>        {/* Column for human-readable anomaly reason */}
              </tr>
            </thead>
            <tbody> {/* Table body where actual log rows are rendered */}
              {logs.map((log) => ( // Iterate over each log entry
                <tr key={log.id} className={log.is_anomaly ? 'anomaly' : ''}> {/* Apply 'anomaly' class if flagged */}
                  <td>{log.time_received}</td>       {/* Show when log was received */}
                  <td>{log.src_ip}</td>              {/* Show source IP address */}
                  <td>{log.action}</td>              {/* Show action taken */}
                  <td>{log.status_code}</td>         {/* Show HTTP status code */}
                  <td>{log.is_anomaly ? 'Yes' : 'No'}</td> {/* Indicate anomaly presence */}
                  <td>{log.confidence_score}</td>    {/* Show confidence score */}
                  <td>{log.anomaly_reason || '-'}</td> {/* Show reason or dash if absent/DNE */}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>No logs available.</p> // Message that appears when no logs are present
      )}
        </div>
    )}
    </div>
  );
};

export default App; // Export component
