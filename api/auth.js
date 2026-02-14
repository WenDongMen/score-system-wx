/* ===============================
   登录状态检查（增强版 + 兼容修复）
================================ */
function checkLogin() {
  const token = localStorage.getItem('token');
  const userInfo = localStorage.getItem('userInfo');

  // 无token/用户信息 → 跳登录页
  if (!token || !userInfo) {
    // 避免重复跳转（当前已经是登录页则不跳转）
    const currentPath = window.location.pathname;
    if (currentPath !== '/login' && currentPath !== '/login.html') {
      window.location.replace('/login?t=' + Date.now()); // 强制跳转，避免缓存
    }
    return false;
  }

  try {
    const user = JSON.parse(userInfo);
    // 额外校验token有效性（简单过期检查）
    if (token.split('.').length === 3) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        // 检查token是否过期（exp是秒级时间戳）
        if (payload.exp && payload.exp < Date.now() / 1000) {
          alert('登录已过期，请重新登录');
          logout();
          return false;
        }
      } catch (e) {
        logout();
        return false;
      }
    }
    return user;
  } catch (e) {
    logout();
    return false;
  }
}

/* ===============================
   登录
================================ */
async function login() {
  // 1. 强制获取DOM元素（避免null），增加容错
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const msg = document.getElementById('msg');
  const loginBtn = document.getElementById('loginBtn'); // 用ID精准获取按钮

  // 元素校验，避免JS报错中断
  if (!usernameInput || !passwordInput || !msg || !loginBtn) {
    alert('页面加载异常，请刷新后重试！');
    return;
  }

  // 2. 防重复点击
  if (loginBtn.disabled) return;
  
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();

  // 3. 清空之前的错误提示
  msg.textContent = '';
  msg.style.color = 'red';

  // 4. 参数校验
  if (!username) {
    msg.textContent = '请输入用户名';
    usernameInput.focus();
    return;
  }
  
  if (!password) {
    msg.textContent = '请输入密码';
    passwordInput.focus();
    return;
  }

  // 5. 登录中状态
  loginBtn.disabled = true;
  loginBtn.textContent = '登录中...';
  msg.textContent = '正在验证账号信息...';
  msg.style.color = '#666';

  try {
    // 6. 兼容所有浏览器的超时处理（替换AbortSignal.timeout）
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10秒超时

    // 7. 发起登录请求
    const res = await fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password }),
      signal: controller.signal
    });

    clearTimeout(timeoutId); // 清除超时器

    // 8. 非200状态码直接抛错
    if (!res.ok) {
      throw new Error(`请求失败：${res.status}`);
    }

    const data = await res.json();

    // 9. 业务码非200处理
    if (data.code !== 200) {
      msg.textContent = data.message || '登录失败，请检查账号密码';
      msg.style.color = 'red';
      loginBtn.disabled = false;
      loginBtn.textContent = '登录'; // 提前恢复按钮
      return;
    }

    // 10. 登录成功
    localStorage.setItem('token', data.token || '');
    localStorage.setItem('userInfo', JSON.stringify(data.user || {}));
    
    msg.textContent = '登录成功，正在跳转...';
    msg.style.color = 'green';

    // 11. 简化跳转逻辑
    const redirectUrl = (() => {
      switch (data.user?.role) {
        case 'teacher': return '/teacher';
        case 'admin': return '/admin';
        case 'student': return '/student';
        default: return '';
      }
    })();

    if (redirectUrl) {
      // 双重跳转保障（href + replace），缩短延迟
      setTimeout(() => {
        window.location.href = redirectUrl;
        window.location.replace(redirectUrl); // 兜底确保跳转
      }, 500);
    } else {
      msg.textContent = '未知角色，无法跳转';
      msg.style.color = 'red';
      loginBtn.disabled = false;
      loginBtn.textContent = '登录';
    }

  } catch (err) {
    console.error('登录异常：', err);
    msg.textContent = '网络错误或服务器异常，请稍后再试';
    msg.style.color = 'red';
    loginBtn.disabled = false;
    loginBtn.textContent = '登录'; // 异常时恢复按钮
  }
}

/* ===============================
   退出登录
================================ */
function logout() {
  // 清除所有登录态
  localStorage.removeItem('token');
  localStorage.removeItem('userInfo');
  // 强制跳转登录页（避免缓存，用replace）
  window.location.replace('/login?t=' + Date.now());
}

/* ===============================
   角色校验（增强版 + 修复跳转）
================================ */
function checkRole(requiredRole) {
  const user = checkLogin();
  if (!user) return false;

  if (user.role !== requiredRole) {
    alert(`无权限访问！该页面仅允许【${requiredRole}】角色访问`);
    logout(); // 强制跳登录页
    return false;
  }
  // 校验通过，返回用户信息
  return user;
}

/* ===============================
   辅助函数：更新首页登录状态
================================ */
function updateLoginStatusUI() {
  // 适配index.ejs的登录状态展示
  const loginStatus = document.getElementById('loginStatus');
  const loginBtn = document.getElementById('loginBtn');
  const adminBtn = document.getElementById('adminBtn');
  
  if (!loginStatus) return; // 非首页则不执行

  const user = checkLogin();
  if (user) {
    // 已登录状态
    loginStatus.textContent = `已登录（${user.role}）`;
    loginStatus.className = 'stat-value ok';
    loginBtn.textContent = '进入工作台';
    loginBtn.href = user.role === 'teacher' ? '/teacher' : '/admin';
    
    if (adminBtn) {
      adminBtn.href = user.role === 'teacher' ? '/teacher' : '/admin';
      adminBtn.textContent = user.role === 'teacher' ? '教师工作台' : '管理员后台';
    }
  } else {
    // 未登录状态
    loginStatus.textContent = '未登录';
    loginStatus.className = 'stat-value warn';
    loginBtn.textContent = '登录系统';
    loginBtn.href = '/login';
    
    if (adminBtn) {
      adminBtn.href = '/login';
      adminBtn.textContent = '后台管理';
    }
  }
}

/* ===============================
   自动为请求添加Token（关键！）
================================ */
function setupAuthHeader() {
  const token = localStorage.getItem('token');
  if (!token) return;

  // 重写fetch，自动添加Authorization头
  const originalFetch = window.fetch;
  window.fetch = function(url, options = {}) {
    options.headers = options.headers || {};
    if (!options.headers.Authorization) {
      options.headers.Authorization = `Bearer ${token}`;
    }
    return originalFetch(url, options);
  };

  // 重写XMLHttpRequest，兼容所有请求
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    originalOpen.apply(this, arguments);
    this.setRequestHeader('Authorization', `Bearer ${token}`);
  };
}

/* ===============================
   页面初始化（核心！）
================================ */
window.addEventListener('DOMContentLoaded', function() {
  // 1. 自动为所有请求添加Token（确保pageAuth能拿到）
  setupAuthHeader();

  // 2. 首页更新登录状态
  const currentPath = window.location.pathname;
  if (currentPath === '/' || currentPath === '/index') {
    updateLoginStatusUI();
  }
  
  // 3. 自动校验角色权限
  if (currentPath === '/teacher') {
    checkRole('teacher');
  } else if (currentPath === '/admin') {
    checkRole('admin');
  } else if (currentPath === '/student') {
    checkRole('student');
  }
});