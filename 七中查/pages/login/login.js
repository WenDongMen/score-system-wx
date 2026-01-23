Page({
  data: {
    account: '', // 账号
    password: '', // 密码
    showPwd: false, // 密码是否可见
    isLoading: false, // 登录加载状态
    errorMsg: '', // 错误提示信息
    imageErrors: { // 图片加载错误状态（用于兜底显示）
      loginIcon: false,
      userIcon: false,
      pwdIcon: false,
      eyeOpen: false,
      eyeClose: false
    }
  },

  /**
   * 生命周期函数--监听页面加载
   */
  onLoad(options) {
    // 读取缓存的账号，自动填充（提升用户体验）
    const savedAccount = wx.getStorageSync('savedAccount');
    if (savedAccount) {
      this.setData({ account: savedAccount });
    }
  },

  /**
   * 处理图片加载失败事件
   * @param {Object} e - 事件对象
   */
  handleImageError(e) {
    const { type } = e.currentTarget.dataset;
    this.setData({
      [`imageErrors.${type}`]: true
    });
  },

  /**
   * 账号输入框绑定事件
   * @param {Object} e - 输入事件对象
   */
  bindAccountInput(e) {
    const value = e.detail.value.trim();
    this.setData({
      account: value,
      errorMsg: '' // 输入时清空错误提示
    });
  },

  /**
   * 密码输入框绑定事件
   * @param {Object} e - 输入事件对象
   */
  bindPwdInput(e) {
    const value = e.detail.value.trim();
    this.setData({
      password: value,
      errorMsg: '' // 输入时清空错误提示
    });
  },

  /**
   * 切换密码可见性
   */
  togglePwdVisible() {
    this.setData({
      showPwd: !this.data.showPwd
    });
  },

  /**
   * 跳转到忘记密码页面（可根据实际需求实现）
   */
  goToForgot() {
    wx.showModal({
      title: '提示',
      content: '学生请联系班主任恢复密码，教师请联系管理员恢复密码',
      showCancel: false,
      confirmText: '我知道了'
    });
  },

  /**
   * 核心登录逻辑
   */
  handleLogin() {
    const { account, password, isLoading } = this.data;

    // 1. 防重复点击
    if (isLoading) return;

    // 2. 输入验证（增强合法性校验）
    const validateResult = this._validateInput(account, password);
    if (!validateResult.valid) {
      this.setData({ errorMsg: validateResult.msg });
      return;
    }

    // 3. 发起登录请求
    this.setData({ isLoading: true, errorMsg: '' });
    wx.request({
      url: 'http://192.168.101.114/login', // 替换为实际后端接口地址
      method: 'POST',
      data: {
        username: account,
        password: password
      },
      header: {
        'Content-Type': 'application/json'
      },
      timeout: 10000, // 超时时间10秒
      success: (res) => {
        this._handleLoginSuccess(res);
      },
      fail: (err) => {
        this._handleLoginFail(err);
      },
      complete: () => {
        // 无论成功失败，结束加载状态
        this.setData({ isLoading: false });
      }
    });
  },

  /**
   * 私有方法：输入验证
   * @param {string} account - 账号
   * @param {string} password - 密码
   * @returns {Object} 验证结果
   */
  _validateInput(account, password) {
    // 账号为空
    if (!account) {
      return { valid: false, msg: '请输入学生姓名/账号' };
    }
    // 账号长度限制（根据实际需求调整）
    if (account.length > 10) {
      return { valid: false, msg: '账号长度不能超过10个字符' };
    }
    // 密码为空
    if (!password) {
      return { valid: false, msg: '请输入密码' };
    }
    // 密码长度限制（根据实际需求调整）
    if (password.length < 6 || password.length > 20) {
      return { valid: false, msg: '密码长度需为6-20位' };
    }
    // 验证通过
    return { valid: true };
  },

  /**
   * 私有方法：处理登录成功逻辑
   * @param {Object} res - 接口返回结果
   */
  _handleLoginSuccess(res) {
    const { data } = res;
    // 登录成功判断（健壮的判空逻辑）
    if (data?.code === 200 && data?.token && data?.user) {
      // 保存用户信息到本地缓存（异步操作，避免阻塞）
      wx.setStorage({
        key: 'savedAccount',
        data: this.data.account
      });
      wx.setStorage({
        key: 'token',
        data: data.token
      });
      wx.setStorage({
        key: 'userInfo',
        data: data.user
      });

      // 角色与页面映射（便于维护）
      const rolePageMap = {
        student: { path: '/pages/student/student', text: '学生' },
        teacher: { path: '/pages/teacher/teacher', text: '教师' },
        admin: { path: '/pages/admin/admin', text: '管理员' }
      };
      const userRole = data.user.role;
      const roleConfig = rolePageMap[userRole];

      if (!roleConfig) {
        this.setData({ errorMsg: '未知用户角色，请联系管理员' });
        return;
      }

      // 登录成功提示
      wx.showToast({
        title: '登录成功',
        icon: 'success',
        duration: 1500
      });

      // 延迟跳转（等待提示框显示）
      setTimeout(() => {
        wx.reLaunch({
          url: roleConfig.path,
          success: () => {
            console.log(`跳转${roleConfig.text}页面成功`);
          },
          fail: (err) => {
            this._handlePageJumpFail(err, roleConfig);
          }
        });
      }, 1500);
    } else {
      // 登录失败处理
      const failMsg = data?.message || '登录失败，请检查账号密码';
      this.setData({ errorMsg: failMsg });
    }
  },

  /**
   * 私有方法：处理登录请求失败（网络/超时等）
   * @param {Object} err - 错误信息
   */
  _handleLoginFail(err) {
    console.error('登录请求失败:', err);
    let errMsg = '网络错误，请检查网络连接';
    if (err.errMsg.includes('timeout')) {
      errMsg = '请求超时，请确认后端服务已启动';
    } else if (err.errMsg.includes('connect')) {
      errMsg = '连接失败，请检查后端IP和端口';
    }
    this.setData({ errorMsg: errMsg });
  },

  /**
   * 私有方法：处理页面跳转失败
   * @param {Object} err - 跳转错误信息
   * @param {Object} roleConfig - 角色配置
   */
  _handlePageJumpFail(err, roleConfig) {
    console.error(`${roleConfig.text}页面跳转失败:`, err);
    wx.showModal({
      title: '跳转失败',
      content: `页面路径错误：${err.errMsg}\n请检查app.json中是否配置${roleConfig.path}`,
      showCancel: false,
      confirmText: '我知道了'
    });
  }
});