const express = require("express");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const app = express();
const port = 3000;

// Middleware for parsing JSON bodies
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// Multer configuration remains the same as previous version
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  },
});

// Enhanced data structures
let users = [
  {
    id: 1,
    username: "admin",
    password: "$2b$10$...", // hashed password
    email: "admin@example.com",
    roles: "ADMIN",
    favorites: [],
  },
];

let webtoons = [
  {
    id: 1,
    title: "The Great Adventure",
    author: "John Doe",
    genre: "Action",
    description: "An epic journey across dimensions",
    thumbnail: "url/to/main/thumbnail",
    status: "ONGOING",
    publishDay: "MONDAY",
    rating: 4.5,
    totalRatings: 100,
    viewCount: 5000,
    tags: ["action", "adventure", "fantasy"],
    episodes: [
      {
        episodeNumber: 1,
        title: "The Beginning",
        thumbnailUrl: "url/to/thumbnail1",
        content: [
          {
            type: "image",
            url: "url/to/panel1",
            order: 1,
          },
        ],
        likeCount: 1000,
        comments: [
          {
            id: 1,
            userId: 1,
            username: "user1",
            content: "Great episode!",
            createdAt: "2024-02-14T12:00:00Z",
            likes: 50,
          },
        ],
        viewCount: 1000,
        publishDate: "2024-02-14",
        isLocked: false,
      },
    ],
  },
];

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token)
    return res.status(401).json({ message: "Authentication required" });

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Role-based authorization middleware
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
};

// User Authentication Routes
app.post("/api/register", async (req, res) => {
  const { username, password, email, roles } = req.body;

  if (users.some((u) => u.username === username)) {
    return res.status(400).json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    username,
    password: hashedPassword,
    email,
    roles: roles ?? "USER",
    favorites: [],
  };

  users.push(newUser);
  res
    .status(201)
    .json({
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      roles: newUser.roles,
      favorites: newUser.favorites,
    });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    "your-secret-key",
    { expiresIn: "24h" }
  );
  res.json({ token });
});

// Image Upload Routes
app.post(
  "/api/upload",
  authenticateToken,
  upload.single("image"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }
    res.json({ url: `/uploads/${req.file.filename}` });
  }
);

// Webtoon Routes
app.get("/api/webtoons", (req, res) => {
  const { genre, author, status, publishDay, page = 1, limit = 10 } = req.query;
  let results = [...webtoons];

  if (genre) {
    results = results.filter(
      (w) => w.genre.toLowerCase() === genre.toLowerCase()
    );
  }

  if (author) {
    results = results.filter((w) =>
      w.author.toLowerCase().includes(author.toLowerCase())
    );
  }

  if (status) {
    results = results.filter((w) => w.status === status.toUpperCase());
  }

  if (publishDay) {
    results = results.filter((w) => w.publishDay === publishDay.toUpperCase());
  }

  // Calculate pagination
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  const paginatedResults = {
    data: results.slice(startIndex, endIndex),
    total: results.length,
    currentPage: parseInt(page),
    totalPages: Math.ceil(results.length / limit),
    hasNext: endIndex < results.length,
    hasPrevious: startIndex > 0,
  };

  res.json(paginatedResults);
});

// GET single webtoon by ID
app.get("/api/webtoons/:id", (req, res) => {
  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });
  res.json(webtoon);
});

// GET episodes list of a webtoon
app.get("/api/webtoons/:id/episodes", (req, res) => {
  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

  // Return episode list without content
  const episodesList = webtoon.episodes.map(
    ({ content, ...episode }) => episode
  );
  res.json(episodesList);
});

// GET specific episode with content
app.get("/api/webtoons/:id/episodes/:episodeNumber", (req, res) => {
  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

  const episode = webtoon.episodes.find(
    (e) => e.episodeNumber === parseInt(req.params.episodeNumber)
  );
  if (!episode) return res.status(404).json({ message: "Episode not found" });

  res.json(episode);
});

// Rating system
app.post("/api/webtoons/:id/rate", authenticateToken, (req, res) => {
  const { rating } = req.body;
  if (rating < 1 || rating > 5) {
    return res.status(400).json({ message: "Rating must be between 1 and 5" });
  }

  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

  webtoon.totalRatings = (webtoon.totalRatings || 0) + 1;
  webtoon.rating = (
    (webtoon.rating * (webtoon.totalRatings - 1) + rating) /
    webtoon.totalRatings
  ).toFixed(1);

  res.json({ rating: webtoon.rating, totalRatings: webtoon.totalRatings });
});

// Comments system
app.post(
  "/api/webtoons/:id/episodes/:episodeNumber/comments",
  authenticateToken,
  (req, res) => {
    const { content } = req.body;

    const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
    if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

    const episode = webtoon.episodes.find(
      (e) => e.episodeNumber === parseInt(req.params.episodeNumber)
    );
    if (!episode) return res.status(404).json({ message: "Episode not found" });

    const newComment = {
      id: episode.comments.length + 1,
      userId: req.user.id,
      username: req.user.username,
      content,
      createdAt: new Date().toISOString(),
      likes: 0,
    };

    episode.comments.push(newComment);
    res.status(201).json(newComment);
  }
);

app.post("/api/comments/:commentId/like", authenticateToken, (req, res) => {
  let foundComment;
  let episode;

  for (const webtoon of webtoons) {
    for (const ep of webtoon.episodes) {
      const comment = ep.comments.find(
        (c) => c.id === parseInt(req.params.commentId)
      );
      if (comment) {
        foundComment = comment;
        episode = ep;
        break;
      }
    }
  }

  if (!foundComment) {
    return res.status(404).json({ message: "Comment not found" });
  }

  foundComment.likes += 1;
  res.json(foundComment);
});

// Content management routes
app.post(
  "/api/webtoons",
  authenticateToken,
  authorize(["ADMIN", "AUTHOR"]),
  upload.single("thumbnail"),
  (req, res) => {
    const newWebtoon = {
      id: webtoons.length + 1,
      title: req.body.title,
      author: req.user.username,
      genre: req.body.genre,
      description: req.body.description,
      thumbnail: req.file ? `/uploads/${req.file.filename}` : null,
      status: req.body.status || "ONGOING",
      publishDay: req.body.publishDay,
      rating: 0,
      totalRatings: 0,
      viewCount: 0,
      episodes: [],
    };

    webtoons.push(newWebtoon);
    res.status(201).json(newWebtoon);
  }
);
app.post(
  "/api/webtoons/:id/episodes",
  authenticateToken,
  authorize(["ADMIN", "AUTHOR"]),
  upload.array("panels"),
  (req, res) => {
    const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
    if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

    if (webtoon.author !== req.user.username && req.user.role !== "ADMIN") {
      return res
        .status(403)
        .json({ message: "Unauthorized to add episodes to this webtoon" });
    }

    const newEpisode = {
      episodeNumber: webtoon.episodes.length + 1,
      title: req.body.title,
      thumbnailUrl: req.files[0] ? `/uploads/${req.files[0].filename}` : null,
      content: req.files.map((file, index) => ({
        type: "image",
        url: `/uploads/${file.filename}`,
        order: index + 1,
      })),
      likeCount: 0,
      comments: [],
      viewCount: 0,
      publishDate:
        req.body.publishDate || new Date().toISOString().split("T")[0],
      isLocked: req.body.isLocked === "true",
    };

    webtoon.episodes.push(newEpisode);
    res.status(201).json(newEpisode);
  }
);

// PUT update episode content
app.put("/api/webtoons/:id/episodes/:episodeNumber/content", (req, res) => {
  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

  const episode = webtoon.episodes.find(
    (e) => e.episodeNumber === parseInt(req.params.episodeNumber)
  );
  if (!episode) return res.status(404).json({ message: "Episode not found" });

  episode.content = req.body.content;
  res.json(episode);
});

// PUT update webtoon
app.put("/api/webtoons/:id", (req, res) => {
  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

  webtoon.title = req.body.title || webtoon.title;
  webtoon.author = req.body.author || webtoon.author;
  webtoon.genre = req.body.genre || webtoon.genre;
  webtoon.description = req.body.description || webtoon.description;
  webtoon.thumbnail = req.body.thumbnail || webtoon.thumbnail;
  webtoon.status = req.body.status || webtoon.status;
  webtoon.publishDay = req.body.publishDay || webtoon.publishDay;

  res.json(webtoon);
});

// DELETE webtoon
app.delete("/api/webtoons/:id", (req, res) => {
  const webtoonIndex = webtoons.findIndex(
    (w) => w.id === parseInt(req.params.id)
  );
  if (webtoonIndex === -1)
    return res.status(404).json({ message: "Webtoon not found" });

  webtoons.splice(webtoonIndex, 1);
  res.status(204).send();
});

// DELETE episode
app.delete("/api/webtoons/:id/episodes/:episodeNumber", (req, res) => {
  const webtoon = webtoons.find((w) => w.id === parseInt(req.params.id));
  if (!webtoon) return res.status(404).json({ message: "Webtoon not found" });

  const episodeIndex = webtoon.episodes.findIndex(
    (e) => e.episodeNumber === parseInt(req.params.episodeNumber)
  );
  if (episodeIndex === -1)
    return res.status(404).json({ message: "Episode not found" });

  webtoon.episodes.splice(episodeIndex, 1);
  res.status(204).send();
});

/// User Favorites/Bookmarks System
app.post("/api/favorites/:webtoonId", authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user.favorites) user.favorites = [];

  if (!user.favorites.includes(parseInt(req.params.webtoonId))) {
    user.favorites.push(parseInt(req.params.webtoonId));
  }

  res.json({ favorites: user.favorites });
});

app.delete("/api/favorites/:webtoonId", authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  user.favorites = user.favorites.filter(
    (id) => id !== parseInt(req.params.webtoonId)
  );
  res.json({ favorites: user.favorites });
});

app.get("/api/favorites", authenticateToken, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: "User  not found" });
  }

  const favoriteWebtoons = webtoons.filter((w) =>
    user.favorites.includes(w.id)
  );

  res.json(favoriteWebtoons);
});

// Enhanced Search with Pagination
app.get("/api/search", (req, res) => {
  const { query, genre, status, page = 1, limit = 10 } = req.query;

  let results = [...webtoons];

  if (query) {
    const searchTerm = query.toLowerCase();
    results = results.filter(
      (w) =>
        w.title.toLowerCase().includes(searchTerm) ||
        w.description.toLowerCase().includes(searchTerm) ||
        w.tags.some((tag) => tag.toLowerCase().includes(searchTerm))
    );
  }

  if (genre) {
    results = results.filter(
      (w) => w.genre.toLowerCase() === genre.toLowerCase()
    );
  }

  if (status) {
    results = results.filter(
      (w) => w.status.toLowerCase() === status.toLowerCase()
    );
  }

  // Calculate pagination
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  const paginatedResults = {
    data: results.slice(startIndex, endIndex),
    total: results.length,
    currentPage: parseInt(page),
    totalPages: Math.ceil(results.length / limit),
    hasNext: endIndex < results.length,
    hasPrevious: startIndex > 0,
  };

  res.json(paginatedResults);
});

app.listen(port, () => {
  console.log(`Webtoon API running on port ${port}`);
});
