// 核心依赖引入
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dayjs = require('dayjs');
const crypto = require('crypto');
const path = require('path'); 

// 初始化Express应用
const app = express();
const PORT = process.env.PORT || 80;
const ENV = process.env.ENV || 'production';

// ===================== EJS模板引擎配置（核心新增） =====================
// 设置EJS为模板引擎
app.set('view engine', 'ejs');
// 配置模板文件目录（views），适配项目目录结构，__dirname为当前文件所在目录
app.set('views', path.join(__dirname, 'views'));
// 可选：配置静态资源目录（如css、js、img），前端页面可直接引用
app.use(express.static(path.join(__dirname, 'public')));

// ===================== 基础配置 =====================
// 中间件配置
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// ===================== 常量配置 =====================
// 数据库配置
const DB_CONFIG = {
  host: process.env.DB_HOST || 'dpg-d5m9ag14tr6s73cfopo0-a.virginia-postgres.render.com',
  port: parseInt(process.env.DB_PORT) || 5432,
  user: process.env.DB_USER || 'score_db_dqiq_user',
  password: process.env.DB_PASSWORD || '6CncyAag2G5oZO1xzD8ivWLwX7KERH2v',
  database: process.env.DB_NAME || 'score_db_dqiq',
  connectTimeoutMillis: 15000,
  ssl: { rejectUnauthorized: false } // Render PostgreSQL要求SSL
};

// JWT配置
const SECRET_KEY = process.env.SECRET_KEY || 'score-system-secret-key-2026';
const TOKEN_EXPIRE_HOURS = parseInt(process.env.TOKEN_EXPIRE_HOURS) || 24;

// 安全配置
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// ===================== 日志工具 =====================
const logAudit = (operation, userId, username, remoteAddr, details = "", level = "INFO") => {
  const logObj = {
    time: dayjs().format('YYYY-MM-DD HH:mm:ss'),
    level,
    operation,
    userId: userId || -1,
    username: username || 'unknown',
    remoteAddr: remoteAddr || 'unknown',
    details
  };
  console.log(`[AUDIT] ${JSON.stringify(logObj)}`);
};

// ===================== 数据库工具 =====================
// 创建数据库连接池（全局唯一）
const pool = new Pool({
  host: DB_CONFIG.host,
  port: DB_CONFIG.port,
  user: DB_CONFIG.user,
  password: DB_CONFIG.password,
  database: DB_CONFIG.database,
  connectTimeoutMillis: DB_CONFIG.connectTimeoutMillis,
  ssl: DB_CONFIG.ssl,
  max: 10 // 连接池最大连接数
});

// 测试数据库连接
const testDbConnection = async () => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    console.log('✅ PostgreSQL数据库连接成功');
    return true;
  } catch (err) {
    console.error('❌ 数据库连接失败：', err.message);
    return false;
  }
};

// 初始化数据库表结构
const initializeDatabase = async () => {
  let client = null;
  try {
    client = await pool.connect();
    
    // 创建用户表
    const createUserTable = `
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL CHECK (role IN ('student', 'teacher', 'admin')),
        id_card VARCHAR(18) UNIQUE,
        class_name VARCHAR(50),
        bind_time TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `;
    await client.query(createUserTable);

    // 创建成绩表
    const createScoreTable = `
      CREATE TABLE IF NOT EXISTS scores (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        subject VARCHAR(50) NOT NULL,
        score FLOAT NOT NULL,
        exam_date DATE NOT NULL,
        created_by INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE (user_id, subject, exam_date)
      );
    `;
    await client.query(createScoreTable);

    // 插入默认管理员账号
    const adminUsername = 'admin001';
    const adminPassword = 'Admin@123456';
    const adminResult = await client.query(
      `SELECT id FROM users WHERE username = $1 LIMIT 1`,
      [adminUsername]
    );

    if (adminResult.rows.length === 0) {
      const hashedAdminPwd = bcrypt.hashSync(adminPassword, BCRYPT_ROUNDS);
      await client.query(`
        INSERT INTO users (username, password, role)
        VALUES ($1, $2, 'admin')
      `, [adminUsername, hashedAdminPwd]);
      console.log(`✅ 默认管理员账号创建成功：${adminUsername}/${adminPassword}`);
    }

    // 插入默认教师账号
    const teacherUsername = 'teacher001';
    const teacherPassword = '123456';
    const teacherResult = await client.query(
      `SELECT id FROM users WHERE username = $1 LIMIT 1`,
      [teacherUsername]
    );

    if (teacherResult.rows.length === 0) {
      const hashedTeacherPwd = bcrypt.hashSync(teacherPassword, BCRYPT_ROUNDS);
      await client.query(`
        INSERT INTO users (username, password, role, id_card, class_name)
        VALUES ($1, $2, 'teacher', NULL, NULL)
      `, [teacherUsername, hashedTeacherPwd]);
      console.log(`✅ 默认教师账号创建成功：${teacherUsername}/${teacherPassword}`);
    }

    console.log('✅ 数据库表结构初始化完成');
  } catch (err) {
    console.error('❌ 数据库初始化失败：', err.message);
    logAudit('数据库初始化', -1, 'system', 'localhost', `错误：${err.message}`, 'ERROR');
  } finally {
    if (client) {
      client.release();
    }
  }
};

// ===================== 安全工具 =====================
// 密码哈希
const hashPassword = (plainPassword) => {
  const salt = bcrypt.genSaltSync(BCRYPT_ROUNDS);
  return bcrypt.hashSync(plainPassword, salt);
};

// 验证密码
const verifyPassword = (plainPassword, hashedPassword) => {
  return bcrypt.compareSync(plainPassword, hashedPassword);
};

// 生成JWT
const generateJwt = (userId, username, role) => {
  const expire = dayjs().add(TOKEN_EXPIRE_HOURS, 'hour').unix();
  return jwt.sign(
    { user_id: userId, username, role, exp: expire, iat: dayjs().unix() },
    SECRET_KEY,
    { algorithm: 'HS256' }
  );
};

// 验证JWT
const verifyJwt = (token) => {
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    return {
      user_id: payload.user_id,
      username: payload.username,
      role: payload.role
    };
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      logAudit('验证JWT', -1, 'unknown', 'unknown', 'Token已过期', 'WARNING');
    } else {
      logAudit('验证JWT', -1, 'unknown', 'unknown', `Token无效：${err.message}`, 'WARNING');
    }
    return null;
  }
};

// XSS过滤
const xssEscape = (data) => {
  if (typeof data === 'string') {
    return data
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  } else if (Array.isArray(data)) {
    return data.map(xssEscape);
  } else if (typeof data === 'object' && data !== null) {
    const result = {};
    for (const key in data) {
      result[key] = xssEscape(data[key]);
    }
    return result;
  }
  return data;
};

// 密码强度验证
const validatePasswordStrength = (password) => {
  if (password.length < 8) {
    return { valid: false, message: '密码长度至少8位' };
  }
  
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const ruleCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  
  if (ruleCount < 3) {
    return { valid: false, message: '密码需包含大小写字母、数字、特殊字符中的至少3种' };
  }
  
  return { valid: true, message: '密码复杂度符合要求' };
};

// ===================== 成绩统计工具 =====================
// 计算级部排名
const calculateGradeRank = async (examDate, subject, score) => {
  let client = null;
  try {
    client = await pool.connect();
    const result = await client.query(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM scores 
      WHERE exam_date = $1 AND subject = $2 AND score > $3
    `, [examDate, subject, score]);
    
    return (result.rows[0].count || 0) + 1;
  } catch (err) {
    logAudit('计算级部排名', -1, 'system', 'unknown', `错误：${err.message}`, 'WARNING');
    return 0;
  } finally {
    if (client) client.release();
  }
};

// 计算班级排名
const calculateClassRank = async (userId, examDate, subject, score) => {
  let client = null;
  try {
    client = await pool.connect();
    // 获取学生班级
    const userResult = await client.query(`
      SELECT class_name FROM users WHERE id = $1 LIMIT 1
    `, [userId]);
    
    if (!userResult.rows[0]?.class_name) return 0;
    const className = userResult.rows[0].class_name;
    
    // 计算排名
    const result = await client.query(`
      SELECT COUNT(DISTINCT s.user_id) as count
      FROM scores s
      JOIN users u ON s.user_id = u.id
      WHERE s.exam_date = $1 AND s.subject = $2 AND s.score > $3 AND u.class_name = $4
    `, [examDate, subject, score, className]);
    
    return (result.rows[0].count || 0) + 1;
  } catch (err) {
    logAudit('计算班级排名', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return 0;
  } finally {
    if (client) client.release();
  }
};

// 判断是否级部前十
const isGradeTopTen = async (examDate, subject, score) => {
  let client = null;
  try {
    client = await pool.connect();
    const result = await client.query(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM scores 
      WHERE exam_date = $1 AND subject = $2 AND score > $3
    `, [examDate, subject, score]);
    
    return (result.rows[0].count || 0) < 10;
  } catch (err) {
    logAudit('判断级部前十', -1, 'system', 'unknown', `错误：${err.message}`, 'WARNING');
    return false;
  } finally {
    if (client) client.release();
  }
};

// 获取历史总分
const getExamHistoryScores = async (userId) => {
  let client = null;
  try {
    client = await pool.connect();
    const result = await client.query(`
      SELECT 
        exam_date,
        SUM(score) AS total_score
      FROM scores 
      WHERE user_id = $1 
      GROUP BY exam_date 
      ORDER BY exam_date ASC
    `, [userId]);
    
    return result.rows.map(row => ({
      exam_date: dayjs(row.exam_date).format('YYYY-MM-DD'),
      total_score: Math.round(Number(row.total_score) * 10) / 10
    }));
  } catch (err) {
    logAudit('获取历史总分', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return [];
  } finally {
    if (client) client.release();
  }
};

// 获取单科历史成绩
const getSubjectHistoryScores = async (userId) => {
  let client = null;
  try {
    client = await pool.connect();
    const result = await client.query(`
      SELECT 
        subject,
        exam_date,
        score
      FROM scores 
      WHERE user_id = $1 
      ORDER BY subject ASC, exam_date ASC
    `, [userId]);
    
    const subjectData = {};
    result.rows.forEach(row => {
      const subject = row.subject;
      if (!subjectData[subject]) {
        subjectData[subject] = {
          subject,
          history: []
        };
      }
      
      subjectData[subject].history.push({
        exam_date: dayjs(row.exam_date).format('YYYY-MM-DD'),
        score: Math.round(Number(row.score) * 10) / 10
      });
    });
    
    return Object.values(subjectData);
  } catch (err) {
    logAudit('获取单科历史成绩', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return [];
  } finally {
    if (client) client.release();
  }
};

// 计算总分排名
const calculateExamTotalRank = async (userId, examDate, totalScore) => {
  let client = null;
  try {
    client = await pool.connect();
    // 获取学生班级
    const userResult = await client.query(`
      SELECT class_name FROM users WHERE id = $1 LIMIT 1
    `, [userId]);
    const className = userResult.rows[0]?.class_name;
    
    // 级部排名
    const gradeResult = await client.query(`
      SELECT COUNT(DISTINCT s1.user_id) AS rank_count
      FROM (
        SELECT user_id, SUM(score) AS total
        FROM scores 
        WHERE exam_date = $1 
        GROUP BY user_id
      ) s1
      WHERE s1.total > $2
    `, [examDate, totalScore]);
    
    const gradeRank = (gradeResult.rows[0].rank_count || 0) + 1;
    
    // 班级排名
    let classRank = 0;
    if (className) {
      const classResult = await client.query(`
        SELECT COUNT(DISTINCT s1.user_id) AS rank_count
        FROM (
          SELECT s.user_id, SUM(s.score) AS total
          FROM scores s
          JOIN users u ON s.user_id = u.id
          WHERE s.exam_date = $1 AND u.class_name = $2
          GROUP BY s.user_id
        ) s1
        WHERE s1.total > $3
      `, [examDate, className, totalScore]);
      
      classRank = (classResult.rows[0].rank_count || 0) + 1;
    }
    
    return { grade_rank: gradeRank, class_rank: classRank };
  } catch (err) {
    logAudit('计算总分排名', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return { grade_rank: 0, class_rank: 0 };
  } finally {
    if (client) client.release();
  }
};

// 获取排名变化
const getRankChange = async (userId, examDate, currentGradeRank) => {
  const history = await getExamHistoryScores(userId);
  if (history.length < 2) {
    return { type: 'same', desc: '首次考试，无排名变化', change: 0 };
  }
  
  const examDates = history.map(item => item.exam_date);
  if (!examDates.includes(examDate)) {
    return { type: 'same', desc: '无排名变化', change: 0 };
  }
  
  const currentIdx = examDates.indexOf(examDate);
  if (currentIdx === 0) {
    return { type: 'same', desc: '首次考试，无排名变化', change: 0 };
  }
  
  const lastExamDate = history[currentIdx - 1].exam_date;
  const lastTotalScore = history[currentIdx - 1].total_score;
  const lastRankData = await calculateExamTotalRank(userId, lastExamDate, lastTotalScore);
  const lastGradeRank = lastRankData.grade_rank;
  
  const change = lastGradeRank - currentGradeRank;
  if (change > 0) {
    return { type: 'up', desc: `进步${change}名`, change };
  } else if (change < 0) {
    return { type: 'down', desc: `退步${Math.abs(change)}名`, change: Math.abs(change) };
  } else {
    return { type: 'same', desc: '排名不变', change: 0 };
  }
};

// ===================== 中间件 =====================
// 认证中间件
const authRequired = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json(xssEscape({
        code: 401,
        message: '未登录，请先登录'
      }));
    }
    
    const token = authHeader.split(' ')[1].trim();
    const userInfo = verifyJwt(token);
    
    if (!userInfo) {
      return res.status(401).json(xssEscape({
        code: 401,
        message: '登录已过期或Token无效，请重新登录'
      }));
    }
    
    // 检查角色权限
    if (req.roleRequired && userInfo.role !== req.roleRequired) {
      logAudit('权限校验', userInfo.user_id, userInfo.username, req.ip, 
               `无${req.roleRequired}角色权限，操作被拒绝`, 'WARNING');
      
      return res.status(403).json(xssEscape({
        code: 403,
        message: `权限不足，仅支持${req.roleRequired}角色操作`
      }));
    }
    
    req.userInfo = userInfo;
    next();
  } catch (err) {
    logAudit('认证中间件异常', -1, 'unknown', req.ip, `错误：${err.message}`, 'ERROR');
    return res.status(500).json(xssEscape({
      code: 500,
      message: '认证失败'
    }));
  }
};

// 角色要求中间件
const requireRole = (role) => {
  return (req, res, next) => {
    req.roleRequired = role;
    authRequired(req, res, next);
  };
};

// 管理员权限中间件
const requireAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json(xssEscape({
        code: 401,
        message: '未登录，请先登录'
      }));
    }
    
    const token = authHeader.split(' ')[1].trim();
    const userInfo = verifyJwt(token);
    
    if (!userInfo || userInfo.role !== 'admin') {
      logAudit('管理员权限校验', userInfo?.user_id || -1, userInfo?.username || 'unknown', req.ip, 
               '无管理员权限，操作被拒绝', 'WARNING');
      
      return res.status(403).json(xssEscape({
        code: 403,
        message: '权限不足，仅管理员可操作'
      }));
    }
    
    req.userInfo = userInfo;
    next();
  } catch (err) {
    logAudit('管理员认证异常', -1, 'unknown', req.ip, `错误：${err.message}`, 'ERROR');
    return res.status(500).json(xssEscape({
      code: 500,
      message: '认证失败'
    }));
  }
};

// 异常处理中间件
const handleException = (apiName) => {
  return (req, res, next) => {
    try {
      next();
    } catch (err) {
      const userId = req.userInfo?.user_id || -1;
      const username = req.userInfo?.username || 'unknown';
      
      logAudit(apiName, userId, username, req.ip, `异常：${err.message}`, 'ERROR');
      console.error(err.stack);
      
      return res.status(500).json(xssEscape({
        code: 500,
        message: '服务器内部错误，请稍后重试'
      }));
    }
  };
};

// ===================== API接口 =====================
// 新增：EJS页面渲染根路由（核心整合点）
app.get('/', async (req, res) => {
  try {
    const healthStatus = '正常运行';
    const now = dayjs().format('YYYY-MM-DD HH:mm:ss');

    res.render('index', {
      title: '成绩管理系统 - 首页',
      systemName: '学生成绩管理系统',
      healthStatus,
      env: ENV,
      now,
      user: null  
    });
  } catch (err) {
    res.status(500).send('页面加载失败：' + err.message);
  }
});


// 原有根路径调整为/info，避免和EJS渲染路由冲突
app.get('/info', (req, res) => {
  res.json({
    code:200,
    message: '成绩管理系统后端服务启动成功！，如有问题请联系作者15684199141（微信同号）',
    time: dayjs().format('YYYY-MM-DD HH:mm:ss')
  });
});

app.get('/test', (req, res) => {
  res.json({
    status: 'ok',
    message: '服务运行正常',
    time: new Date().toLocaleString()
  });
});

app.get('/api/me', (req, res) => {
  // 现在先写死，假装没登录
  res.json({
    loggedIn: false,
    user: null
  });
});


// 健康检查
app.get('/api/health', (req, res) => {
  res.json({
    code: 200,
    message: '服务正常',
    env: ENV,
    time: dayjs().format('YYYY-MM-DD HH:mm:ss')
  });
});

// 登录接口
app.route('/login')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get((req, res) => {
    res.json(xssEscape({
      code: 200,
      message: '登录接口正常，请使用POST提交JSON数据',
      time: dayjs().format('YYYY-MM-DD HH:mm:ss')
    }));
  })
  .post(handleException('用户登录'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      if (!data) {
        return res.status(415).json(xssEscape({
          code: 400,
          message: '请提交JSON数据（Content-Type: application/json）'
        }));
      }
      
      const username = (data.username || data.account || '').trim();
      const password = (data.password || '').trim();
      
      // 参数验证
      if (!username || !/^[\u4e00-\u9fa5A-Za-z0-9_]{1,50}$/.test(username)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户名仅支持中文、英文、数字、下划线'
        }));
      }
      
      if (!password) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入密码'
        }));
      }
      
      // 查询用户
      client = await pool.connect();
      const result = await client.query(`
        SELECT id, username, password, role, id_card, class_name FROM users WHERE username = $1 LIMIT 1
      `, [username]);
      
      // 1. 账号不存在的情况 - 明确提示
      if (result.rows.length === 0) {
        logAudit('用户登录', -1, username, req.ip, '账号不存在', 'WARNING');
        return res.status(401).json(xssEscape({
          code: 401,
          message: '账号不存在'
        }));
      }
      
      // 2. 账号存在但密码错误的情况 - 提示账号或密码错误
      const user = result.rows[0];
      if (verifyPassword(password, user.password)) {
        const token = generateJwt(user.id, user.username, user.role);
        
        logAudit('用户登录', user.id, user.username, req.ip, 
                 `角色：${user.role}，登录成功`);
        
        return res.json(xssEscape({
          code: 200,
          message: '登录成功',
          token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            id_card: user.id_card,
            class_name: user.class_name
          }
        }));
      } else {
        logAudit('用户登录', user.id, username, req.ip, '密码错误', 'WARNING');
        return res.status(401).json(xssEscape({
          code: 401,
          message: '账号或密码错误'
        }));
      }
    } catch (err) {
      logAudit('登录接口异常', -1, 'unknown', req.ip, `错误：${err.message}`, 'ERROR');
      console.error(err.stack);
      return res.status(500).json(xssEscape({
        code: 500,
        message: '登录失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// -------------------------- 管理员接口 --------------------------
// 查询所有教师
app.route('/api/admin/teachers')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireAdmin, handleException('管理员查询所有教师'), async (req, res) => {
    let client = null;
    try {
      client = await pool.connect();
      const result = await client.query(`
        SELECT id, username, role, created_at 
        FROM users 
        WHERE role = 'teacher' 
        ORDER BY created_at DESC;
      `);
      
      const teachers = result.rows.map(teacher => ({
        ...teacher,
        created_at: teacher.created_at ? dayjs(teacher.created_at).format('YYYY-MM-DD HH:mm:ss') : null
      }));
      
      logAudit('管理员查询所有教师', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `查询到${teachers.length}名教师`);
      
      res.json(xssEscape({
        code: 200,
        message: '查询成功',
        data: teachers
      }));
    } catch (err) {
      logAudit('管理员查询教师异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '查询失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 新增教师
app.route('/api/admin/teacher/add')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireAdmin, handleException('管理员新增教师'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      
      if (!data || !data.username || !data.password) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户名和密码不能为空'
        }));
      }
      
      if (!/^[\u4e00-\u9fa5A-Za-z0-9_]{1,50}$/.test(data.username)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户名仅支持中文、英文、数字、下划线'
        }));
      }
      
      const { valid, message } = validatePasswordStrength(data.password);
      if (!valid) {
        return res.status(400).json(xssEscape({
          code: 400,
          message
        }));
      }
      
      // 检查用户名是否存在
      client = await pool.connect();
      let result = await client.query(`
        SELECT id FROM users WHERE username = $1;
      `, [data.username]);
      
      if (result.rows.length > 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户名已存在'
        }));
      }
      
      // 添加教师
      const hashedPwd = hashPassword(data.password);
      await client.query(`
        INSERT INTO users (username, password, role, id_card, class_name) 
        VALUES ($1, $2, 'teacher', NULL, NULL);
      `, [data.username, hashedPwd]);
      
      // 获取新增教师信息
      result = await client.query(`
        SELECT id, username FROM users WHERE username = $1;
      `, [data.username]);
      
      const newTeacher = result.rows[0];
      logAudit('管理员新增教师', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `新增教师：${data.username}（ID：${newTeacher.id}）`);
      
      res.json(xssEscape({
        code: 200,
        message: '教师添加成功',
        data: newTeacher
      }));
    } catch (err) {
      logAudit('管理员新增教师异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '添加失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 删除教师
app.route('/api/admin/teacher/delete/:teacherId')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .delete(requireAdmin, handleException('管理员删除教师'), async (req, res) => {
    let client = null;
    try {
      const teacherId = parseInt(req.params.teacherId);
      if (isNaN(teacherId)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '教师ID必须是数字'
        }));
      }
      
      client = await pool.connect();
      const result = await client.query(`
        SELECT id, username FROM users WHERE id = $1 AND role = 'teacher';
      `, [teacherId]);
      
      if (result.rows.length === 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '教师不存在'
        }));
      }
      
      const teacher = result.rows[0];
      await client.query(`
        DELETE FROM users WHERE id = $1 AND role = 'teacher';
      `, [teacherId]);
      
      logAudit('管理员删除教师', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `删除教师：${teacher.username}（ID：${teacherId}）`);
      
      res.json(xssEscape({
        code: 200,
        message: '教师删除成功'
      }));
    } catch (err) {
      logAudit('管理员删除教师异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '删除失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 修复：更改教师密码（原代码误写为删除教师，已修正核心逻辑）
app.route('/api/admin/teacher/password/:teacherId')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .put(requireAdmin, handleException('管理员更改教师密码'), async (req, res) => {
    let client = null;
    try {
      const teacherId = parseInt(req.params.teacherId);
      const { new_password } = req.body;
      
      // 验证ID和新密码
      if (isNaN(teacherId)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '教师ID必须是数字'
        }));
      }
      if (!new_password) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '新密码不能为空'
        }));
      }
      // 密码强度校验
      const { valid, message } = validatePasswordStrength(new_password);
      if (!valid) {
        return res.status(400).json(xssEscape({ code: 400, message }));
      }
      
      // 检查教师是否存在
      client = await pool.connect();
      const result = await client.query(`
        SELECT id, username FROM users WHERE id = $1 AND role = 'teacher';
      `, [teacherId]);
      
      if (result.rows.length === 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '教师不存在'
        }));
      }
      
      // 加密新密码并更新
      const teacher = result.rows[0];
      const hashedNewPwd = hashPassword(new_password);
      await client.query(`
        UPDATE users SET password = $1 WHERE id = $2 AND role = 'teacher';
      `, [hashedNewPwd, teacherId]);
      
      logAudit('管理员更改教师密码', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `修改教师${teacher.username}（ID：${teacherId}）的密码`);
      
      res.json(xssEscape({
        code: 200,
        message: '教师密码修改成功'
      }));
    } catch (err) {
      logAudit('管理员更改教师密码异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '密码修改失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// -------------------------- 教师接口 --------------------------
// 搜索学生
app.route('/api/teacher/student/search')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireRole('teacher'), handleException('教师搜索学生'), async (req, res) => {
    let client = null;
    try {
      const keyword = req.query.keyword?.trim() || '';
      
      if (!keyword) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '搜索关键词不能为空'
        }));
      }
      
      client = await pool.connect();
      const result = await client.query(`
        SELECT id, username AS name, id_card AS idCard, class_name AS className 
        FROM users 
        WHERE role = 'student' 
        AND (username LIKE $1 OR id::text LIKE $2 OR id_card LIKE $3)
        ORDER BY created_at DESC;
      `, [`%${keyword}%`, `%${keyword}%`, `%${keyword}%`]);
      
      const students = result.rows.map(student => ({
        id: student.id,
        name: student.name,
        no: student.id,
        idCard: student.idCard || '',
        className: student.className || ''
      }));
      
      logAudit('教师搜索学生', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `关键词：${keyword}，搜索到${students.length}名学生`);
      
      res.json(xssEscape({
        code: 200,
        message: '搜索成功',
        data: students
      }));
    } catch (err) {
      logAudit('教师搜索学生异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '搜索失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 科目成绩统计
app.route('/api/teacher/subject/statistics')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireRole('teacher'), handleException('教师查询科目统计'), async (req, res) => {
    let client = null;
    try {
      // 可选：接收前端传的考试日期参数，无参数则查所有
      const examDate = req.query.exam_date?.trim() || '';
      
      client = await pool.connect();
      let querySql = `
        SELECT 
          subject,
          AVG(score) as avg_score,       -- 平均分
          MAX(score) as max_score,       -- 最高分
          MIN(score) as min_score,       -- 最低分
          COUNT(*) as student_count      -- 参考人数
        FROM scores 
      `;
      const queryParams = [];
      
      // 如果传了考试日期，添加筛选条件
      if (examDate) {
        querySql += ` WHERE exam_date = $1 `;
        queryParams.push(examDate);
      }
      
      querySql += ` GROUP BY subject ORDER BY subject ASC;`;
      
      const result = await client.query(querySql, queryParams);
      
      // 格式化数据（保留1位小数）
      const statistics = result.rows.map(item => ({
        subject: item.subject,
        avg_score: Math.round(Number(item.avg_score) * 10) / 10,
        max_score: Math.round(Number(item.max_score) * 10) / 10,
        min_score: Math.round(Number(item.min_score) * 10) / 10,
        student_count: Number(item.student_count)
      }));
      
      logAudit('教师查询科目统计', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `考试日期：${examDate || '所有'}，查询到${statistics.length}个科目统计`);
      
      res.json(xssEscape({
        code: 200,
        message: '科目统计查询成功',
        data: statistics
      }));
    } catch (err) {
      logAudit('教师查询科目统计异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '查询失败'
      }));
    } finally {
      if (client) client.release();
    }
  });
  
// 查询学生列表
app.route('/api/teacher/student/list')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireRole('teacher'), handleException('教师查询学生列表'), async (req, res) => {
    let client = null;
    try {
      client = await pool.connect();
      const result = await client.query(`
        SELECT id, username, class_name, created_at 
        FROM users 
        WHERE role = 'student' 
        ORDER BY created_at DESC;
      `);
      
      const students = result.rows.map(student => ({
        ...student,
        created_at: student.created_at ? dayjs(student.created_at).format('YYYY-MM-DD HH:mm:ss') : null
      }));
      
      logAudit('教师查询学生列表', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `查询到${students.length}名学生`);
      
      res.json(xssEscape({
        code: 200,
        message: '查询学生列表成功',
        data: students
      }));
    } catch (err) {
      logAudit('教师查询学生列表异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '查询失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 添加学生
app.route('/api/teacher/student/add')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('teacher'), handleException('教师添加学生'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      
      if (!data) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请提交JSON数据'
        }));
      }
      
      const studentName = data.username?.trim() || '';
      const studentIdCard = data.id_card?.trim() || '';
      const className = data.class_name?.trim() || '';
      
      if (!studentName) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入学生姓名'
        }));
      }
      
      if (!studentIdCard || !/^\d{17}[\dXx]$/.test(studentIdCard)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入18位有效身份证号'
        }));
      }
      
      if (!className) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入班级名称'
        }));
      }
      
      client = await pool.connect();
      
      // 检查身份证号是否已绑定
      let result = await client.query(`
        SELECT id FROM users WHERE id_card = $1 LIMIT 1
      `, [studentIdCard]);
      
      if (result.rows.length > 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '该身份证号已绑定学生'
        }));
      }
      
      // 检查用户名是否存在
      result = await client.query(`
        SELECT id FROM users WHERE username = $1 LIMIT 1
      `, [studentName]);
      
      if (result.rows.length > 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '该学生姓名已存在'
        }));
      }
      
      // 添加学生
      const initialPwd = studentIdCard.slice(-6);
      const hashedPwd = hashPassword(initialPwd);
      
      result = await client.query(`
        INSERT INTO users (username, password, role, id_card, class_name, bind_time)
        VALUES ($1, $2, 'student', $3, $4, CURRENT_TIMESTAMP)
        RETURNING id;
      `, [studentName, hashedPwd, studentIdCard, className]);
      
      const studentId = result.rows[0].id;
      
      logAudit('教师添加学生', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `新增学生：${studentName}（ID：${studentId}，班级：${className}）`);
      
      res.json(xssEscape({
        code: 200,
        message: '学生添加成功',
        data: {
          student_id: studentId,
          student_name: studentName,
          class_name: className,
          initial_password: initialPwd
        }
      }));
    } catch (err) {
      logAudit('教师添加学生异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '添加失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 添加成绩
app.route('/api/teacher/add-score')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('teacher'), handleException('教师添加成绩'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      
      if (!data) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请提交JSON数据'
        }));
      }
      
      const studentId = data.student_id;
      const subject = data.subject?.trim() || '';
      const score = data.score;
      const examDate = data.exam_date?.trim() || '';
      
      if (!studentId || typeof studentId !== 'number') {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请选择有效学生'
        }));
      }
      
      if (!subject) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入科目名称'
        }));
      }
      
      if (score === undefined || typeof score !== 'number' || score < 0 || score > 100) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入0-100的有效分数'
        }));
      }
      
      if (!examDate || !/^\d{4}-\d{2}-\d{2}$/.test(examDate)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入正确格式的考试日期（如2024-06-30）'
        }));
      }
      
      client = await pool.connect();
      
      // 检查学生是否存在
      let result = await client.query(`
        SELECT id, username FROM users WHERE id = $1 AND role = 'student' LIMIT 1
      `, [studentId]);
      
      if (result.rows.length === 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '所选学生不存在'
        }));
      }
      
      const student = result.rows[0];
      
      // 检查成绩是否已存在
      result = await client.query(`
        SELECT id FROM scores 
        WHERE user_id = $1 AND subject = $2 AND exam_date = $3 
        LIMIT 1
      `, [studentId, subject, examDate]);
      
      if (result.rows.length > 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: `该学生${examDate}的${subject}成绩已存在`
        }));
      }
      
      // 添加成绩
      await client.query(`
        INSERT INTO scores (user_id, subject, score, exam_date, created_by)
        VALUES ($1, $2, $3, $4, $5)
      `, [studentId, subject, score, examDate, req.userInfo.user_id]);
      
      logAudit('教师添加成绩', req.userInfo.user_id, req.userInfo.username, req.ip, 
               `为学生${student.username}（ID：${studentId}）添加${examDate}的${subject}成绩：${score}`);
      
      res.json(xssEscape({
        code: 200,
        message: `成功添加${student.username}的${subject}成绩`,
        data: {
          student_name: student.username,
          subject,
          score,
          exam_date: examDate
        }
      }));
    } catch (err) {
      logAudit('教师添加成绩异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '添加失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 教师修改密码
app.route('/api/teacher/change-password')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('teacher'), handleException('教师修改密码'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      
      if (!data) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请提交JSON数据'
        }));
      }
      
      const oldPassword = data.old_password?.trim() || '';
      const newPassword = data.new_password?.trim() || '';
      const userId = req.userInfo.user_id;
      
      if (!oldPassword) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入原密码'
        }));
      }
      
      const { valid, message } = validatePasswordStrength(newPassword);
      if (!valid) {
        return res.status(400).json(xssEscape({
          code: 400,
          message
        }));
      }
      
      if (oldPassword === newPassword) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '新密码不能与原密码相同'
        }));
      }
      
      // 验证原密码
      client = await pool.connect();
      const result = await client.query(`
        SELECT password FROM users WHERE id = $1 LIMIT 1
      `, [userId]);
      
      if (result.rows.length === 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户不存在'
        }));
      }
      
      const user = result.rows[0];
      if (!verifyPassword(oldPassword, user.password)) {
        logAudit('教师修改密码', userId, req.userInfo.username, req.ip, '原密码错误', 'WARNING');
        return res.status(400).json(xssEscape({
          code: 400,
          message: '原密码错误'
        }));
      }
      
      // 修改密码
      const hashedNewPwd = hashPassword(newPassword);
      await client.query(`
        UPDATE users SET password = $1 WHERE id = $2
      `, [hashedNewPwd, userId]);
      
      logAudit('教师修改密码', userId, req.userInfo.username, req.ip, '密码修改成功');
      
      res.json(xssEscape({
        code: 200,
        message: '密码修改成功，请重新登录'
      }));
    } catch (err) {
      logAudit('教师修改密码异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '修改失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// -------------------------- 学生接口 --------------------------
// 查询自身成绩
app.route('/api/student/score/my')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('student'), handleException('学生查询自身成绩'), async (req, res) => {
    let client = null;
    try {
      const userId = req.userInfo.user_id;
      client = await pool.connect();
      
      const result = await client.query(`
        SELECT 
          subject,
          score,
          exam_date
        FROM scores 
        WHERE user_id = $1 
        ORDER BY exam_date DESC, subject ASC
      `, [userId]);
      
      // 按考试日期分组
      const examGroup = {};
      for (const item of result.rows) {
        const examDate = dayjs(item.exam_date).format('YYYY-MM-DD');
        
        if (!examGroup[examDate]) {
          examGroup[examDate] = {
            exam_date: examDate,
            subjects: [],
            total_score: 0.0,
            subject_count: 0
          };
        }
        
        // 判断是否级部前十
        const isTopTen = await isGradeTopTen(examDate, item.subject, item.score);
        
        examGroup[examDate].subjects.push({
          subject: item.subject,
          score: Math.round(Number(item.score) * 10) / 10,
          exam_date: examDate,
          is_grade_top_ten: isTopTen
        });
        
        examGroup[examDate].total_score += Number(item.score);
        examGroup[examDate].subject_count += 1;
      }
      
      // 计算排名
      const examList = [];
      for (const [examDate, data] of Object.entries(examGroup)) {
        const rankData = await calculateExamTotalRank(userId, examDate, data.total_score);
        
        examList.push({
          exam_date: data.exam_date,
          total_score: Math.round(data.total_score * 10) / 10,
          subject_count: data.subject_count,
          grade_rank: rankData.grade_rank,
          class_rank: rankData.class_rank,
          subjects: data.subjects
        });
      }
      
      // 按考试日期倒序排序
      examList.sort((a, b) => dayjs(b.exam_date).unix() - dayjs(a.exam_date).unix());
      
      // 获取历史成绩
      const historyScores = await getExamHistoryScores(userId);
      const subjectHistory = await getSubjectHistoryScores(userId);
      
      logAudit('学生查询自身成绩', userId, req.userInfo.username, req.ip, 
               `查询到${examList.length}次考试成绩`);
      
      res.json(xssEscape({
        code: 200,
        message: '成绩查询成功',
        data: {
          exam_list: examList,
          history_scores: historyScores,
          subject_history: subjectHistory
        }
      }));
    } catch (err) {
      logAudit('学生查询自身成绩异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '查询失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 查询考试详情
app.route('/api/student/score/detail')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('student'), handleException('学生查询考试详情'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      
      if (!data || !data.exam_date) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请传入考试日期'
        }));
      }
      
      const examDate = data.exam_date.trim();
      const userId = req.userInfo.user_id;
      
      client = await pool.connect();
      const result = await client.query(`
        SELECT 
          subject,
          score,
          exam_date
        FROM scores 
        WHERE user_id = $1 AND exam_date = $2
        ORDER BY subject ASC
      `, [userId, examDate]);
      
      if (result.rows.length === 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '该考试日期无成绩数据'
        }));
      }
      
      // 计算总分和排名
      const totalScore = result.rows.reduce((sum, item) => sum + Number(item.score), 0);
      const rankData = await calculateExamTotalRank(userId, examDate, totalScore);
      const rankChange = await getRankChange(userId, examDate, rankData.grade_rank);
      
      // 处理单科数据
      const subjectList = [];
      for (const item of result.rows) {
        const subject = item.subject;
        const score = Number(item.score);
        
        subjectList.push({
          subject,
          score: Math.round(score * 10) / 10,
          exam_date: examDate,
          is_grade_top_ten: await isGradeTopTen(examDate, subject, score),
          grade_rank: await calculateGradeRank(examDate, subject, score),
          class_rank: await calculateClassRank(userId, examDate, subject, score)
        });
      }
      
      // 获取历史成绩
      const historyScores = await getExamHistoryScores(userId);
      const subjectHistory = await getSubjectHistoryScores(userId);
      
      logAudit('学生查询考试详情', userId, req.userInfo.username, req.ip, 
               `查询${examDate}考试详情，共${subjectList.length}科成绩`);
      
      res.json(xssEscape({
        code: 200,
        message: '考试详情查询成功',
        data: {
          exam_date: examDate,
          total_score: Math.round(totalScore * 10) / 10,
          grade_rank: rankData.grade_rank,
          class_rank: rankData.class_rank,
          rank_change: rankChange,
          subjects: subjectList,
          history_scores: historyScores,
          subject_history: subjectHistory
        }
      }));
    } catch (err) {
      logAudit('学生查询考试详情异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '查询失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// 学生修改密码
app.route('/api/student/change-password')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('student'), handleException('学生修改密码'), async (req, res) => {
    let client = null;
    try {
      const data = req.body;
      
      if (!data) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请提交JSON数据'
        }));
      }
      
      const oldPassword = data.old_password?.trim() || '';
      const newPassword = data.new_password?.trim() || '';
      const userId = req.userInfo.user_id;
      
      if (!oldPassword) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入原密码'
        }));
      }
      
      const { valid, message } = validatePasswordStrength(newPassword);
      if (!valid) {
        return res.status(400).json(xssEscape({
          code: 400,
          message
        }));
      }
      
      if (oldPassword === newPassword) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '新密码不能与原密码相同'
        }));
      }
      
      // 验证原密码
      client = await pool.connect();
      const result = await client.query(`
        SELECT password FROM users WHERE id = $1 LIMIT 1
      `, [userId]);
      
      if (result.rows.length === 0) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户不存在'
        }));
      }
      
      const user = result.rows[0];
      if (!verifyPassword(oldPassword, user.password)) {
        logAudit('学生修改密码', userId, req.userInfo.username, req.ip, '原密码错误', 'WARNING');
        return res.status(400).json(xssEscape({
          code: 400,
          message: '原密码错误'
        }));
      }
      
      // 修改密码
      const hashedNewPwd = hashPassword(newPassword);
      await client.query(`
        UPDATE users SET password = $1 WHERE id = $2
      `, [hashedNewPwd, userId]);
      
      logAudit('学生修改密码', userId, req.userInfo.username, req.ip, '密码修改成功');
      
      res.json(xssEscape({
        code: 200,
        message: '密码修改成功，请重新登录'
      }));
    } catch (err) {
      logAudit('学生修改密码异常', req.userInfo.user_id, req.userInfo.username, req.ip, `错误：${err.message}`, 'ERROR');
      return res.status(500).json(xssEscape({
        code: 500,
        message: '修改失败'
      }));
    } finally {
      if (client) client.release();
    }
  });

// ===================== 启动服务 =====================
// 初始化数据库并启动服务
const startServer = async () => {
  try {
    // 测试数据库连接
    const isConnected = await testDbConnection();
    if (!isConnected) {
      console.error('❌ 数据库连接失败，服务启动终止');
      process.exit(1);
    }
    
    // 初始化数据库
    await initializeDatabase();
    
    // 启动HTTP服务
    app.listen(PORT, () => {
      console.log('='.repeat(60));
      console.log('成绩管理系统正在启动');
      console.log('成绩管理系统后端服务+EJS页面渲染启动成功！');
      console.log(`服务环境：${ENV}`);
      console.log(`服务地址：http://localhost:${PORT}`);
      console.log(`默认管理员账号：admin001/Admin@123456`);
      console.log(`默认教师账号：teacher001/123456`);
      console.log('='.repeat(60));
    });
  } catch (err) {
    console.error('❌ 服务启动失败：', err.message);
    process.exit(1);
  }
};

// 启动服务
startServer();
