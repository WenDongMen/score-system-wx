// 登录
async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const msg = document.getElementById('msg');

  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();

  if (data.code === 200) {
    localStorage.setItem('token', data.token);
    location.href = '/teacher';
  } else {
    msg.innerText = data.message;
  }
}

// 页面校验
function checkLogin() {
  const token = localStorage.getItem('token');
  if (!token) {
    location.href = '/login';
  }
}

// 退出
function logout() {
  localStorage.removeItem('token');
  location.href = '/login';
}
