Page({
  data: {
    userInfo: {
      username: 'student001',
      id_card: '',
      class_name: '高一(1)班'
    },
    showPwdDialog: false,
    showOldPwd: false,
    showNewPwd: false,
    showConfirmPwd: false,
    oldPwdValue: '',
    newPwdValue: '',
    confirmPwdValue: '',
    pwdMsg: '',
    pwdStrength: {},
    submitting: false,
    maskAnimation: '',
    dialogAnimation: ''
  },

  onLoad() {
    this.checkLoginStatus();
    // 初始化动画
    this.initAnimations();
  },

  /**
   * 初始化动画实例，修复弹窗动画位置
   */
  initAnimations() {
    this.maskAni = wx.createAnimation({
      duration: 300,
      timingFunction: 'ease-out'
    });
    this.dialogAni = wx.createAnimation({
      duration: 300,
      timingFunction: 'ease-out'
    });
    // 初始状态（隐藏）
    this.maskAni.opacity(0).step();
    this.dialogAni.opacity(0).scale(0.9).step();
    this.setData({
      maskAnimation: this.maskAni.export(),
      dialogAnimation: this.dialogAni.export()
    });
  },

  /**
   * 检查登录状态
   */
  checkLoginStatus() {
    try {
      const userInfo = wx.getStorageSync("userInfo") || this.data.userInfo;
      const token = wx.getStorageSync("token") || 'mock-token';
      // 验证用户信息有效性
      if (!userInfo || !token || userInfo.role !== "student") {
        wx.showToast({
          title: '请先登录学生账号',
          icon: 'none',
          duration: 1500
        });
        setTimeout(() => {
          wx.reLaunch({ url: "/pages/login/login" });
        }, 1500);
        return;
      }
      this.setData({ userInfo });
    } catch (err) {
      console.error('检查登录状态失败：', err);
      wx.showToast({
        title: '登录状态异常',
        icon: 'none'
      });
    }
  },

  /**
   * 格式化身份证号
   * @param {string} idCard - 身份证号
   * @returns {string} 格式化后的身份证号
   */
  formatIdCard(idCard) {
    if (!idCard) return '未绑定';
    // 验证身份证格式
    if (!/^\d{18}$/.test(idCard)) {
      return '身份证格式错误';
    }
    return idCard.substring(0, 6) + '********' + idCard.substring(14);
  },

  /**
   * 显示密码修改弹窗
   */
  showPwdDialog() {
    // 重置表单数据
    this.setData({
      showPwdDialog: true,
      oldPwdValue: '',
      newPwdValue: '',
      confirmPwdValue: '',
      pwdMsg: '',
      pwdStrength: {},
      showOldPwd: false,
      showNewPwd: false,
      showConfirmPwd: false,
      submitting: false
    });
    // 执行显示动画
    this.maskAni.opacity(1).step();
    this.dialogAni.opacity(1).scale(1).step();
    this.setData({
      maskAnimation: this.maskAni.export(),
      dialogAnimation: this.dialogAni.export()
    });
  },

  /**
   * 隐藏密码修改弹窗
   */
  hidePwdDialog() {
    // 执行隐藏动画
    this.maskAni.opacity(0).step();
    this.dialogAni.opacity(0).scale(0.9).step();
    this.setData({
      maskAnimation: this.maskAni.export(),
      dialogAnimation: this.dialogAni.export()
    });
    // 动画结束后隐藏弹窗
    setTimeout(() => {
      this.setData({ showPwdDialog: false });
    }, 300);
  },

  /**
   * 切换原密码显示/隐藏
   */
  toggleOldPwd() {
    this.setData({ showOldPwd: !this.data.showOldPwd });
  },

  /**
   * 切换新密码显示/隐藏
   */
  toggleNewPwd() {
    this.setData({ showNewPwd: !this.data.showNewPwd });
  },

  /**
   * 切换确认密码显示/隐藏
   */
  toggleConfirmPwd() {
    this.setData({ showConfirmPwd: !this.data.showConfirmPwd });
  },

  /**
   * 输入原密码
   * @param {Object} e - 输入事件
   */
  inputOldPwd(e) {
    this.setData({ oldPwdValue: e.detail.value });
  },

  /**
   * 输入确认密码
   * @param {Object} e - 输入事件
   */
  inputConfirmPwd(e) {
    this.setData({ confirmPwdValue: e.detail.value });
  },

  /**
   * 检查密码强度
   * @param {Object} e - 输入事件
   */
  checkPwdStrength(e) {
    const newPwd = e.detail.value;
    this.setData({ newPwdValue: newPwd });

    if (!newPwd) {
      this.setData({ pwdStrength: {} });
      return;
    }

    // 优化密码强度判断逻辑
    let strength = { text: '弱', class: 'strength-weak' };
    const len = newPwd.length;
    const hasNumber = /\d/.test(newPwd);
    const hasLetter = /[a-zA-Z]/.test(newPwd);
    const hasSpecial = /[^a-zA-Z0-9]/.test(newPwd);
    const typeCount = [hasNumber, hasLetter, hasSpecial].filter(Boolean).length;

    if (len >= 6 && len < 8) {
      strength = typeCount >= 2 ? { text: '中', class: 'strength-middle' } : strength;
    } else if (len >= 8) {
      if (typeCount === 3) {
        strength = { text: '强', class: 'strength-strong' };
      } else if (typeCount >= 2) {
        strength = { text: '中', class: 'strength-middle' };
      }
    }

    this.setData({ pwdStrength: strength });
  },

  /**
   * 处理密码修改提交
   * @param {Object} e - 表单提交事件
   */
  handleChangePwd(e) {
    const { oldPwd, newPwd, confirmPwd } = e.detail.value;
    let msg = '';

    // 表单验证
    if (!oldPwd) {
      msg = '请输入原密码';
    } else if (!newPwd) {
      msg = '请输入新密码';
    } else if (newPwd.length < 6 || newPwd.length > 20) {
      msg = '新密码长度必须为6-20位';
    } else if (!confirmPwd) {
      msg = '请确认新密码';
    } else if (newPwd !== confirmPwd) {
      msg = '两次输入的密码不一致';
    } else if (newPwd === oldPwd) {
      msg = '新密码不能与原密码相同';
    }

    if (msg) {
      this.setData({ pwdMsg: msg });
      setTimeout(() => {
        this.setData({ pwdMsg: '' });
      }, 2000);
      return;
    }

    // 提交密码修改
    this.submitPwdChange(oldPwd, newPwd);
  },

  /**
   * 提交密码修改请求
   * @param {string} oldPwd - 原密码
   * @param {string} newPwd - 新密码
   */
  submitPwdChange(oldPwd, newPwd) {
    this.setData({ submitting: true });

    // 模拟接口请求
    setTimeout(() => {
      try {
        this.setData({ submitting: false });
        wx.showToast({ title: '密码修改成功', icon: 'success' });
        setTimeout(() => {
          this.hidePwdDialog();
        }, 1500);
      } catch (err) {
        console.error('密码修改失败：', err);
        this.setData({ submitting: false });
        wx.showToast({ title: '密码修改失败，请重试', icon: 'none' });
      }
    }, 1000);
  },

  /**
   * 跳转到成绩页面
   */
  gotoScorePage() {
    wx.navigateTo({
      url: "/pages/score/score",
      fail: (err) => {
        console.log("跳转失败：", err);
        wx.showToast({ title: '页面路径错误', icon: 'none' });
      }
    });
  },

  /**
   * 处理退出登录
   */
  handleLogout() {
    wx.showModal({
      title: '确认退出',
      content: '确定要退出当前账号吗？',
      confirmText: '退出',
      cancelText: '取消',
      success: (res) => {
        if (res.confirm) {
          try {
            // 清除本地存储
            wx.removeStorageSync("token");
            wx.removeStorageSync("userInfo");
            // 跳转到登录页
            wx.reLaunch({ url: "/pages/login/login" });
            wx.showToast({ title: '已退出登录', icon: 'success' });
          } catch (err) {
            console.error('退出登录失败：', err);
            wx.showToast({ title: '退出失败，请重试', icon: 'none' });
          }
        }
      }
    });
  },

  /**
   * 空函数（用于阻止事件冒泡）
   */
  noop() {}
});