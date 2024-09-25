const multer = require('multer');
const path = require('path');

// Set storage engine
const storage = multer.diskStorage({
  destination: './uploads/',  // Define where to store images
  filename: (req, file, cb) => {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

// Check file type
const checkFileType = (file, cb) => {
  const filetypes = /jpeg|jpg|png/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
};

// Init upload
const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 },  // 1MB limit
  fileFilter: (req, file, cb) => {
    checkFileType(file, cb);
  }
});

module.exports = upload;
