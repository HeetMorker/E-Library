const app = require('./app');
const dotenv = require('dotenv');
const connectDB = require('./config/db'); 

dotenv.config();

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  connectDB();  // Ensure the database is connected
  console.log(`Server running on localhost:${PORT}`);
});
