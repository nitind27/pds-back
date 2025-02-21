const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.FRONT_URL, 
  credentials: true
  }));

// JWT Secret Key
const secretKey = process.env.JWT_SECRET || "be5c701d7b261e7cec659a9e361dcded66544da8c1c0930ac57a600d8fbba17f9895fd3f173c1f11608ef295c7ddce94c27338d94e39365ccb35069c18587a1933da8d3c608aa2d2f22a4bee67c55ce14cae2f82a735f4b406a576ec23088cdd0b2682fda5da3f1a4aaddf5f57e804f59773f625c2684dc830b5f42dbc60df496c03994665b46b73fb6a0829e4ac3d7e017fcdaed512288e9ce72eb88726a473bab260d1729e874b988d8c6217e3c8003cf9701b97cc3b2d0299c8fbbace8846e74fcc472536bc04866b2d6ff081c4752e221cf84303cf7da1f4ce0905fced8d";

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "pdsmanagement",
  port: process.env.DB_PORT || 3306,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    return;
  }
  console.log("Connected to MySQL database.");
});


// // Create Employee Table (if not exists)
// db.query(`
//   CREATE TABLE IF NOT EXISTS employees (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     category VARCHAR(50),
//     fullName VARCHAR(100),
//     username VARCHAR(50),
//     password VARCHAR(255),
//     address TEXT,
//     aadharNo VARCHAR(20),
//     panNo VARCHAR(20),
//     bankName VARCHAR(100),
//     accountNumber VARCHAR(50),
//     ifscCode VARCHAR(20),
//     branchName VARCHAR(100),
//     subGodown VARCHAR(100)
//   )
// `, (err) => {
//   if (err) console.error("Error creating employees table:", err);
// });

// // Create Users Table (for Authentication)
// db.query(`
//   CREATE TABLE IF NOT EXISTS signup (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     name VARCHAR(100),
//     surname VARCHAR(100),
//     phone_number VARCHAR(20),
//     email VARCHAR(100) UNIQUE,
//     password VARCHAR(255)
//   )
// `, (err) => {
//   if (err) console.error("Error creating users table:", err);
// });

// **Signup API**
app.post("/signup", async (req, res) => {
  try {
    const { name, surname, phone_number, email, password } = req.body;

    if (!name || !surname || !phone_number || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO signup (name, surname, phone_number, email, password) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [name, surname, phone_number, email, hashedPassword], (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error: " + err });
      }
      res.status(201).json({ message: "User registered successfully" });
    });
  } catch (error) {
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// **Login API**
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM signup WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Database error: " + err });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = results[0];

    try {
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: "1h" });

      res.status(200).json({ message: "Login successful", token, user });
    } catch (error) {
      res.status(500).json({ error: "Error comparing passwords" });
    }
  });
});

// **Insert Employee Data API**
app.post("/employees", async (req, res) => {
  try {
    const { category, fullName, username, password, address, aadharNo, panNo, bankName, accountNumber, ifscCode, branchName, subGodown } = req.body;

    if (!category || !fullName || !username || !password || !aadharNo || !panNo || !bankName || !accountNumber || !ifscCode || !branchName || !subGodown) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Hash the password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO employees (category, fullName, username, password, address, aadharNo, panNo, bankName, accountNumber, ifscCode, branchName, subGodown) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, [category, fullName, username, hashedPassword, address, aadharNo, panNo, bankName, accountNumber, ifscCode, branchName, subGodown], (err, result) => {
      if (err) {
        console.error("Error inserting employee data:", err);
        return res.status(500).json({ error: "Database insertion failed" });
      }
      res.status(201).json({ message: "Employee added successfully" });
    });
  } catch (error) {
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// **Get All Employees API**
app.get("/employees", (req, res) => {
  const sql = "SELECT id, category, fullName, username, address, aadharNo, panNo, bankName, accountNumber, ifscCode, branchName, subGodown FROM employees";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching employees:", err);
      return res.status(500).json({ error: "Database fetch failed" });
    }
    res.status(200).json(results);
  });
});

// **Delete Employee API**
app.delete("/employees/:id", (req, res) => {
  const employeeId = req.params.id;
  const sql = "DELETE FROM employees WHERE id = ?";
  db.query(sql, [employeeId], (err, result) => {
    if (err) {
      console.error("Error deleting employee:", err);
      return res.status(500).json({ error: "Failed to delete employee" });
    }
    res.status(200).json({ message: "Employee deleted successfully" });
  });
});
//end of employe




/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//start of mswc godown
app.get("/api/mswcgodown", (req, res) => {
  const sql = "SELECT uuid, godownName, godownUnder, order_number FROM mswc_godowns ORDER BY order_number";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/api/mswcgodown/:uuid", (req, res) => {
  const sql = "SELECT * FROM mswc_godowns WHERE uuid = ?";
  db.query(sql, [req.params.uuid], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ message: "Godown not found" });
    res.json(results[0]);
  });
});

// Add a new MSWC Godown
app.post("/api/mswcgodown", (req, res) => {
  const { godownName, godownUnder, status = "Active" } = req.body;
  const uuid = uuidv4();

  const getMaxOrderSql = "SELECT COALESCE(MAX(order_number), 0) + 1 AS next_order FROM mswc_godowns";

  db.query(getMaxOrderSql, (err, result) => {
    if (err) {
      console.error("Error getting next order number:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }

    const nextOrder = result[0].next_order;
    const insertSql = "INSERT INTO mswc_godowns (uuid, godownName, godownUnder, order_number, status) VALUES (?, ?, ?, ?, ?)";

    db.query(insertSql, [uuid, godownName, godownUnder, nextOrder, status], (insertErr) => {
      if (insertErr) {
        console.error("Error inserting:", insertErr.sqlMessage || insertErr);
        return res.status(500).json({ error: "Database error", details: insertErr.sqlMessage });
      }
      console.log(`✅ New Godown added with order_number: ${nextOrder}, status: ${status}`);
      res.json({ message: "Godown added successfully", uuid, order_number: nextOrder, status });
    });
  });
});

// Update an existing MSWC Godown
app.put("/api/mswcgodown/:uuid", (req, res) => {
  const { godownName, godownUnder, status } = req.body;
  const sql = "UPDATE mswc_godowns SET godownName = ?, godownUnder = ?, status = ? WHERE uuid = ?";
  
  db.query(sql, [godownName, godownUnder, status, req.params.uuid], (err, result) => {
    if (err) {
      console.error("Error updating:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Godown not found" });
    }
    res.json({ message: "Godown updated successfully" });
  });
});



app.delete("/api/mswcgodown/:uuid", (req, res) => {
  const { uuid } = req.params;

  // Step 1: Delete the specific record
  const deleteSql = "DELETE FROM mswc_godowns WHERE uuid = ?";
  db.query(deleteSql, [uuid], (err, result) => {
    if (err) {
      console.error("Error deleting:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Godown not found" });
    }

    console.log(`✅ Deleted Godown with UUID: ${uuid}`);

    // Step 2: Reset order numbers sequentially
    const resetSql1 = "SET @new_order = 0";
    const resetSql2 = "UPDATE mswc_godowns SET order_number = (@new_order := @new_order + 1) ORDER BY order_number";

    db.query(resetSql1, (resetErr1) => {
      if (resetErr1) {
        console.error("Error resetting variable:", resetErr1.sqlMessage || resetErr1);
        return res.status(500).json({ error: "Failed to reset order numbering variable", details: resetErr1.sqlMessage });
      }

      db.query(resetSql2, (resetErr2) => {
        if (resetErr2) {
          console.error("Error resetting order numbers:", resetErr2.sqlMessage || resetErr2);
          return res.status(500).json({ error: "Failed to reset order numbers", details: resetErr2.sqlMessage });
        }

        console.log("✅ Order numbers reset successfully!");
        res.json({ message: "Godown deleted and order numbers reset successfully!" });
      });
    });
  });
});
//end of mswc godown
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////







//////////////////////////////////////////////////////////////////////////////
//part of subgodwon
app.get("/api/godowns", (req, res) => {
  const query = "SELECT godownName FROM mswc_godowns"; // Fetch only godownname

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching godown names:", err);
      return res.status(500).json({ error: "Database query error" });
    }

    res.json(results);
  });
});


app.get("/api/subgodown", (req, res) => {
  const sql = "SELECT uuid, parentGodown, subGodown , status, order_number FROM sub_godown ORDER BY order_number";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/api/subgodown/:uuid", (req, res) => {
  const sql = "SELECT uuid, parentGodown, subGodown , status, order_number FROM sub_godown WHERE uuid = ?";
  db.query(sql, [req.params.uuid], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ message: "Godown not found" });
    res.json(results[0]);
  });
});

app.post("/api/subgodown", (req, res) => {
  const { parentGodown, subGodown, status = "Active" } = req.body;
  const uuid = uuidv4();

  const getMaxOrderSql = "SELECT COALESCE(MAX(order_number), 0) + 1 AS next_order FROM sub_godown";

  db.query(getMaxOrderSql, (err, result) => {
    if (err) {
      console.error("Error getting next order number:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }

    const nextOrder = result[0].next_order;
    const insertSql = "INSERT INTO sub_godown (uuid, parentGodown, subGodown, status, order_number) VALUES (?, ?, ?, ?, ?)";
    
    db.query(insertSql, [uuid, parentGodown, subGodown, status, nextOrder], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ message: "Sub-Godown added successfully", uuid });
    });
  });
});






// Update an existing MSWC Godown
app.put("/api/subgodown/:uuid", (req, res) => {
  const { parentGodown, subGodown, status } = req.body;
  const sql = "UPDATE sub_godown SET parentGodown = ?, subGodown = ?, status = ? WHERE uuid = ?";
  
  db.query(sql, [parentGodown, subGodown, status, req.params.uuid], (err, result) => {
    if (err) {
      console.error("Error updating:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Godown not found" });
    }
    res.json({ message: "Godown updated successfully" });
  });
});

app.delete("/api/subgodown/:uuid", (req, res) => {
  const { uuid } = req.params;

  // Step 1: Delete the specific record
  const deleteSql = "DELETE FROM sub_godown WHERE uuid = ?";
  db.query(deleteSql, [uuid], (err, result) => {
    if (err) {
      console.error("Error deleting:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Godown not found" });
    }

    console.log(`✅ Deleted Godown with UUID: ${uuid}`);

    // Step 2: Reset order numbers sequentially
    const resetSql1 = "SET @new_order = 0";
    const resetSql2 = "UPDATE sub_godown SET order_number = (@new_order := @new_order + 1) ORDER BY order_number";

    db.query(resetSql1, (resetErr1) => {
      if (resetErr1) {
        console.error("Error resetting variable:", resetErr1.sqlMessage || resetErr1);
        return res.status(500).json({ error: "Failed to reset order numbering variable", details: resetErr1.sqlMessage });
      }

      db.query(resetSql2, (resetErr2) => {
        if (resetErr2) {
          console.error("Error resetting order numbers:", resetErr2.sqlMessage || resetErr2);
          return res.status(500).json({ error: "Failed to reset order numbers", details: resetErr2.sqlMessage });
        }

        console.log("✅ Order numbers reset successfully!");
        res.json({ message: "Godown deleted and order numbers reset successfully!" });
      });
    });
  });
});


//////////////////////////////////////////
//start of ownerpage

app.get("/api/owners", (req, res) => {
  const sql = "SELECT uuid, ownerName, contact, address, emailID, order_number FROM owners ORDER BY order_number";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching owners:", err);
      return res.status(500).json({ error: "Database fetch error" });
    }
    res.json(results);
  });
});


app.get("/api/owners/:uuid", (req, res) => {
  const sql = "SELECT uuid, ownerName, contact, address, emailID, order_number FROM owners WHERE uuid = ?";
  db.query(sql, [req.params.uuid], (err, results) => {
    if (err) {
      console.error("Error fetching owner:", err);
      return res.status(500).json({ error: "Database fetch error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Owner not found" });
    }
    res.json(results[0]);
  });
});


app.post("/api/owners", (req, res) => {
  const { ownerName, contact, address, emailID } = req.body;
  if (!ownerName || !contact || !address || !emailID) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const uuid = uuidv4();
  const getMaxOrderSql = "SELECT COALESCE(MAX(order_number), 0) + 1 AS next_order FROM owners";

  db.query(getMaxOrderSql, (err, result) => {
    if (err) {
      console.error("Error getting next order number:", err);
      return res.status(500).json({ error: "Database error" });
    }

    const nextOrder = result[0].next_order;
    const insertSql = "INSERT INTO owners (uuid, ownerName, contact, address, emailID, order_number) VALUES (?, ?, ?, ?, ?, ?)";

    db.query(insertSql, [uuid, ownerName, contact, address, emailID, nextOrder], (insertErr) => {
      if (insertErr) {
        console.error("Error inserting owner:", insertErr);
        return res.status(500).json({ error: "Database insertion failed" });
      }
      res.status(201).json({ message: "Owner added successfully", uuid, order_number: nextOrder });
    });
  });
});


app.put("/api/owners/:uuid", (req, res) => {
  const { ownerName, contact, address, emailID } = req.body;
  if (!ownerName || !contact || !address || !emailID) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const sql = "UPDATE owners SET ownerName = ?, contact = ?, address = ?, emailID = ? WHERE uuid = ?";

  db.query(sql, [ownerName, contact, address, emailID, req.params.uuid], (err, result) => {
    if (err) {
      console.error("Error updating owner:", err);
      return res.status(500).json({ error: "Database update error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Owner not found" });
    }
    res.json({ message: "Owner updated successfully" });
  });
});




app.delete("/api/owners/:uuid", (req, res) => {
  const { uuid } = req.params;

  // Step 1: Delete the specific record
  const deleteSql = "DELETE FROM owners WHERE uuid = ?";
  db.query(deleteSql, [uuid], (err, result) => {
    if (err) {
      console.error("Error deleting owner:", err);
      return res.status(500).json({ error: "Database deletion failed" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Owner not found" });
    }

    console.log(`✅ Deleted Owner with UUID: ${uuid}`);

    // Step 2: Reset order numbers sequentially
    const resetSql1 = "SET @new_order = 0";
    const resetSql2 = "UPDATE owners SET order_number = (@new_order := @new_order + 1) ORDER BY order_number";

    db.query(resetSql1, (resetErr1) => {
      if (resetErr1) {
        console.error("Error resetting order numbers:", resetErr1);
        return res.status(500).json({ error: "Failed to reset order numbering" });
      }

      db.query(resetSql2, (resetErr2) => {
        if (resetErr2) {
          console.error("Error resetting order numbers:", resetErr2);
          return res.status(500).json({ error: "Failed to reset order numbers" });
        }

        console.log("✅ Order numbers reset successfully!");
        res.json({ message: "Owner deleted and order numbers reset successfully!" });
      });
    });
  });
});
//endof ownerpage
///////////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////////////////
///start of grain page

// Get all grains
app.get("/api/grains", (req, res) => {
  const sql = "SELECT * FROM grains ORDER BY order_number";

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching grains:", err);
      return res.status(500).json({ error: "Database query failed" });
    }
    res.json(results);
  });
});

// Get a specific grain by UUID
app.get("/api/grains/:uuid", (req, res) => {
  const { uuid } = req.params;
  const sql = "SELECT * FROM grains WHERE uuid = ?";

  db.query(sql, [uuid], (err, result) => {
    if (err) {
      console.error("Error fetching grain:", err);
      return res.status(500).json({ error: "Database query failed" });
    }
    if (result.length === 0) {
      return res.status(404).json({ message: "Grain not found" });
    }
    res.json(result[0]);
  });
});




app.post("/api/grains", (req, res) => {
  console.log("Incoming Request Body:", req.body); // Debugging log

  const { grainName, godownName } = req.body;

  if (!grainName || !godownName) {
    return res.status(400).json({ error: "Grain name and one Godown selection are required" });
  }

  const uuid = uuidv4();
  const getMaxOrderSql = "SELECT COALESCE(MAX(order_number), 0) + 1 AS next_order FROM grains";

  db.query(getMaxOrderSql, (err, result) => {
    if (err) {
      console.error("Error getting next order number:", err);
      return res.status(500).json({ error: "Database error" });
    }

    const nextOrder = result[0].next_order;
    const insertSql = "INSERT INTO grains (uuid, grainName, godownName, order_number) VALUES (?, ?, ?, ?)";

    db.query(insertSql, [uuid, grainName, godownName, nextOrder], (insertErr) => {
      if (insertErr) {
        console.error("Error inserting grain:", insertErr);
        return res.status(500).json({ error: "Database insertion failed" });
      }
      res.status(201).json({ message: "Grain added successfully", uuid, order_number: nextOrder });
    });
  });
});




app.put("/api/grains/:uuid", (req, res) => {
  const { grainName, mswcGodown, subGodown } = req.body;
  if (!grainName || (!mswcGodown && !subGodown)) {
    return res.status(400).json({ error: "Grain name and one Godown selection are required" });
  }

  const godownName = mswcGodown || subGodown;

  const sql = "UPDATE grains SET grainName = ?, godownName = ? WHERE uuid = ?";

  db.query(sql, [grainName, godownName, req.params.uuid], (err, result) => {
    if (err) {
      console.error("Error updating grain:", err);
      return res.status(500).json({ error: "Database update error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Grain not found" });
    }
    res.json({ message: "Grain updated successfully" });
  });
});

app.delete("/api/grains/:uuid", (req, res) => {
  const { uuid } = req.params;

  const deleteSql = "DELETE FROM grains WHERE uuid = ?";
  db.query(deleteSql, [uuid], (err, result) => {
    if (err) {
      console.error("Error deleting grain:", err);
      return res.status(500).json({ error: "Database deletion failed" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Grain not found" });
    }

    console.log(`✅ Deleted Grain with UUID: ${uuid}`);

    const resetSql1 = "SET @new_order = 0";
    const resetSql2 = "UPDATE grains SET order_number = (@new_order := @new_order + 1) ORDER BY order_number";

    db.query(resetSql1, (resetErr1) => {
      if (resetErr1) {
        console.error("Error resetting order numbers:", resetErr1);
        return res.status(500).json({ error: "Failed to reset order numbering" });
      }

      db.query(resetSql2, (resetErr2) => {
        if (resetErr2) {
          console.error("Error resetting order numbers:", resetErr2);
          return res.status(500).json({ error: "Failed to reset order numbers" });
        }

        console.log("✅ Order numbers reset successfully!");
        res.json({ message: "Grain deleted and order numbers reset successfully!" });
      });
    });
  });
});
///end of grain
///////////////////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// start of truck page
// // Get all trucks with pagination
// app.get("/api/truck", (req, res) => {
//   let { page, limit } = req.query;
//   page = parseInt(page) || 1; 
//   limit = parseInt(limit) || 10; 
//   const offset = (page - 1) * limit;

//   const countSql = "SELECT COUNT(*) AS total FROM truck";
//   db.query(countSql, (countErr, countResult) => {
//     if (countErr) return res.status(500).json({ error: countErr.message });

//     const totalRecords = countResult[0].total;
//     const totalPages = Math.ceil(totalRecords / limit);

//     const sql = "SELECT * FROM truck LIMIT ? OFFSET ?";
//     db.query(sql, [limit, offset], (err, results) => {
//       if (err) return res.status(500).json({ error: err.message });

//       res.json({
//         data: results,
//         pagination: {
//           totalRecords,
//           totalPages,
//           currentPage: page,
//           limit,
//         },
//       });
//     });
//   });
// });

// Get all trucks
app.get("/api/truck", (req, res) => {
  const sql = "SELECT * FROM truck";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Get a specific truck by UUID
app.get("/api/truck/:uuid", (req, res) => {
  const sql = "SELECT * FROM truck WHERE uuid = ?";
  db.query(sql, [req.params.uuid], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ message: "Truck not found" });
    res.json(results[0]);
  });
});

// Add a new truck
app.post("/api/truck", (req, res) => {
  const { truck_name, truck_status = "Active", empty_weight, company, gvw, reg_date, truck_owner_name, owner_id, tax_validity, insurance_validity, fitness_validity, permit_validity, direct_sale } = req.body;
  const uuid = uuidv4();

  const insertSql = "INSERT INTO truck (uuid, truck_name, truck_status, empty_weight, company, gvw, reg_date, truck_owner_name, owner_id, tax_validity, insurance_validity, fitness_validity, permit_validity, direct_sale) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  
  db.query(insertSql, [uuid, truck_name, truck_status, empty_weight, company, gvw, reg_date, truck_owner_name, owner_id, tax_validity, insurance_validity, fitness_validity, permit_validity, direct_sale], (insertErr) => {
    if (insertErr) {
      console.error("Error inserting:", insertErr.sqlMessage || insertErr);
      return res.status(500).json({ error: "Database error", details: insertErr.sqlMessage });
    }
    res.json({ message: "Truck added successfully", uuid });
  });
});

// Update an existing truck
app.put("/api/truck/:uuid", (req, res) => {
  const { truck_name, truck_status, empty_weight, company, gvw, reg_date, truck_owner_name, owner_id, tax_validity, insurance_validity, fitness_validity, permit_validity, direct_sale } = req.body;
  
  const sql = "UPDATE truck SET truck_name = ?, truck_status = ?, empty_weight = ?, company = ?, gvw = ?, reg_date = ?, truck_owner_name = ?, owner_id = ?, tax_validity = ?, insurance_validity = ?, fitness_validity = ?, permit_validity = ?, direct_sale = ? WHERE uuid = ?";
  
  db.query(sql, [truck_name, truck_status, empty_weight, company, gvw, reg_date, truck_owner_name, owner_id, tax_validity, insurance_validity, fitness_validity, permit_validity, direct_sale, req.params.uuid], (err, result) => {
    if (err) {
      console.error("Error updating:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Truck not found" });
    }
    res.json({ message: "Truck updated successfully" });
  });
});

// Delete a truck
app.delete("/api/truck/:uuid", (req, res) => {
  const deleteSql = "DELETE FROM truck WHERE uuid = ?";
  const uuid = uuidv4();
  db.query(deleteSql, [req.params.uuid], (err, result) => {
    if (err) {
      console.error("Error deleting:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Truck not found" });
    }
    res.json({ message: "Truck deleted successfully" });
  });
});

///end of truck
///////////////////////////////////////////////////////////////////////////////////////////////////////////////







///////////////////////////////////////////////////////////////////////////////
///** Start of Packaging */

//✅ Fetch all packaging records
app.get("/api/packaging", (req, res) => {
  const sql = "SELECT * FROM packaging";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Get a specific packaging material by pack_id
app.get("/api/packaging/:pack_id", (req, res) => {
  const sql = "SELECT * FROM packaging WHERE pack_id = ?";
  db.query(sql, [req.params.pack_id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ message: "Packaging material not found" });
    res.json(results[0]);
  });
});

// Add a new packaging material
app.post("/api/packaging", (req, res) => {
  const { material_name, weight, status = "Start" } = req.body;

  const insertSql = "INSERT INTO packaging (material_name, weight, status) VALUES (?, ?, ?)";
  
  db.query(insertSql, [material_name, weight, status], (insertErr, result) => {
    if (insertErr) {
      console.error("Error inserting:", insertErr.sqlMessage || insertErr);
      return res.status(500).json({ error: "Database error", details: insertErr.sqlMessage });
    }
    res.json({ message: "Packaging material added successfully", pack_id: result.insertId });
  });
});

// Update an existing packaging material
app.put("/api/packaging/:pack_id", (req, res) => {
  const { material_name, weight, status } = req.body;
  
  const sql = "UPDATE packaging SET material_name = ?, weight = ?, status = ? WHERE pack_id = ?";
  
  db.query(sql, [material_name, weight, status, req.params.pack_id], (err, result) => {
    if (err) {
      console.error("Error updating:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Packaging material not found" });
    }
    res.json({ message: "Packaging material updated successfully" });
  });
});

// Delete a packaging material
app.delete("/api/packaging/:pack_id", (req, res) => {
  const deleteSql = "DELETE FROM packaging WHERE pack_id = ?";
  db.query(deleteSql, [req.params.pack_id], (err, result) => {
    if (err) {
      console.error("Error deleting:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Packaging material not found" });
    }
    res.json({ message: "Packaging material deleted successfully" });
  });
});

//end of packaging
///////////////////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////
//**Start Categories**
// Get all categories
app.get("/api/categories", (req, res) => {
  const sql = "SELECT * FROM categories";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Get a specific category by category_id
app.get("/api/categories/:category_id", (req, res) => {
  const sql = "SELECT * FROM categories WHERE category_id = ?";
  db.query(sql, [req.params.category_id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ message: "Category not found" });
    res.json(results[0]);
  });
});

// Add a new category
app.post("/api/categories", (req, res) => {
  const { category_name, description } = req.body;

  const insertSql = "INSERT INTO categories (category_name, description) VALUES (?, ?)";
  
  db.query(insertSql, [category_name, description], (insertErr, result) => {
    if (insertErr) {
      console.error("Error inserting:", insertErr.sqlMessage || insertErr);
      return res.status(500).json({ error: "Database error", details: insertErr.sqlMessage });
    }
    res.json({ message: "Category added successfully", category_id: result.insertId });
  });
});

// Update an existing category
app.put("/api/categories/:category_id", (req, res) => {
  const { category_name, description } = req.body;
  
  const sql = "UPDATE categories SET category_name = ?, description = ? WHERE category_id = ?";
  
  db.query(sql, [category_name, description, req.params.category_id], (err, result) => {
    if (err) {
      console.error("Error updating:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json({ message: "Category updated successfully" });
  });
});

// Delete a category
app.delete("/api/categories/:category_id", (req, res) => {
  const deleteSql = "DELETE FROM categories WHERE category_id = ?";
  db.query(deleteSql, [req.params.category_id], (err, result) => {
    if (err) {
      console.error("Error deleting:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json({ message: "Category deleted successfully" });
  });
});

//end of categories
///////////////////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////
// **Start Schemes**

// Get all schemes
app.get("/api/scheme", (req, res) => {
  const sql = "SELECT * FROM scheme";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Get a specific scheme by scheme_id
app.get("/api/scheme/:scheme_id", (req, res) => {
  const sql = "SELECT * FROM scheme WHERE scheme_id = ?";
  db.query(sql, [req.params.scheme_id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ message: "Scheme not found" });
    res.json(results[0]);
  });
});

// Add a new scheme
app.post("/api/scheme", (req, res) => {
  const { scheme_name, scheme_status } = req.body;

  const insertSql = "INSERT INTO scheme (scheme_name, scheme_status) VALUES (?, ?)";

  db.query(insertSql, [scheme_name, scheme_status], (insertErr, result) => {
    if (insertErr) {
      console.error("Error inserting:", insertErr.sqlMessage || insertErr);
      return res.status(500).json({ error: "Database error", details: insertErr.sqlMessage });
    }
    res.json({ message: "Scheme added successfully", scheme_id: result.insertId });
  });
});

// Update an existing scheme
app.put("/api/scheme/:scheme_id", (req, res) => {
  const { scheme_name, scheme_status } = req.body;

  const sql = "UPDATE scheme SET scheme_name = ?, scheme_status = ? WHERE scheme_id = ?";

  db.query(sql, [scheme_name, scheme_status, req.params.scheme_id], (err, result) => {
    if (err) {
      console.error("Error updating:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Scheme not found" });
    }
    res.json({ message: "Scheme updated successfully" });
  });
});

// Delete a scheme
app.delete("/api/scheme/:scheme_id", (req, res) => {
  const deleteSql = "DELETE FROM scheme WHERE scheme_id = ?";
  db.query(deleteSql, [req.params.scheme_id], (err, result) => {
    if (err) {
      console.error("Error deleting:", err.sqlMessage || err);
      return res.status(500).json({ error: "Database error", details: err.sqlMessage });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Scheme not found" });
    }
    res.json({ message: "Scheme deleted successfully" });
  });
});

// **End of Schemes**
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///  COUNT OF CARDS

// API to fetch row counts from multiple tables
app.get("/api/getRowCounts", (req, res) => {
  const query = `
    SELECT 
      (SELECT COUNT(*) FROM owners) AS table1_count,
      (SELECT COUNT(*) FROM employees) AS table2_count,
      (SELECT COUNT(*) FROM mswc_godowns) AS table3_count,
      (SELECT COUNT(*) FROM sub_godown) AS table4_count,
      (SELECT COUNT(*) FROM truck) AS table6_count,
      (SELECT COUNT(*) FROM scheme) AS table7_count,
      (SELECT COUNT(*) FROM packaging) AS table8_count
  `;
  // (SELECT COUNT(*) FROM drivers) AS table5_count,

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const counts = results[0]; // Results will have row counts
    res.json({
      ownercount: counts.table1_count,
      employeecount: counts.table2_count,
      mswccount: counts.table3_count,
      godowncount: counts.table4_count,
      // drivercount: counts.table5_count,
      truckcount: counts.table6_count,
      schemecount: counts.table7_count,
      packagingcount: counts.table8_count,
    });
  });
});



///////////////////////////////////////////////////////////////////////////////////////////

// **Server Listening**
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.get('/', (req, res) => {
  res.send('API is running');
});