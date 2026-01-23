Page({
  data: {
    userInfo: {},
    showPwdDialog: false,
    pwdMsg: '',
    activeTab: 'mine'
  },

  onLoad(options) {
    // 获取教师信息（从缓存或接口获取）
    this.getUserInfo();
    // 固定设置当前tab为“我的”
    this.setData({ activeTab: 'mine' });
  },

  // 获取教师信息
  getUserInfo() {
    const userInfo = wx.getStorageSync('teacherInfo') || {};
    this.setData({ userInfo });
  },

  // 显示密码修改弹窗
  showPwdDialog() {
    this.setData({
      showPwdDialog: true,
      pwdMsg: '' // 清空提示信息
    });
  },

  // 隐藏密码修改弹窗
  hidePwdDialog() {
    this.setData({
      showPwdDialog: false,
      pwdMsg: ''
    });
  },

  // 阻止弹窗点击事件冒泡
  stopPropagation() {},

  // 修改密码提交
  handleChangePwd(e) {
    const { oldPwd, newPwd, confirmPwd } = e.detail.value;
    // 前端校验
    if (!oldPwd) {
      this.setData({ pwdMsg: '请输入原密码' });
      return;
    }
    if (!newPwd || newPwd.length < 6 || newPwd.length > 20) {
      this.setData({ pwdMsg: '请输入6-20位新密码' });
      return;
    }
    if (newPwd !== confirmPwd) {
      this.setData({ pwdMsg: '两次输入的新密码不一致' });
      return;
    }

    // 调用修改密码接口（替换为你的真实接口）
    const token = wx.getStorageSync('token');
    wx.request({
      url: 'http://192.168.101.114/api/teacher/change-password',
      method: 'POST',
      header: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      data: { oldPwd, newPwd },
      success: (res) => {
        if (res.data.code === 200) {
          wx.showToast({ title: '密码修改成功', icon: 'success' });
          this.hidePwdDialog();
        } else {
          this.setData({ pwdMsg: res.data.message || '修改失败' });
        }
      },
      fail: () => {
        this.setData({ pwdMsg: '网络错误，请重试' });
      }
    });
  },

  // 退出登录
  handleLogout() {
    wx.showModal({
      title: '提示',
      content: '确定要退出登录吗？',
      success: (res) => {
        if (res.confirm) {
          // 清空缓存
          wx.removeStorageSync('token');
          wx.removeStorageSync('teacherInfo');
          // 跳转到登录页
          wx.reLaunch({ url: '/pages/login/login' });
        }
      }
    });
  },

  // 跳转到查询页
  goToQuery() {
    // 避免重复跳转：判断当前是否已是查询页
    const pages = getCurrentPages();
    const currentRoute = pages[pages.length - 1].route;
    if (currentRoute === 'pages/teacher/teacher') {
      return;
    }
    wx.redirectTo({
      url: '/pages/teacher/teacher'
    });
  },

  // 跳转到管理页
  goToManage() {
    wx.redirectTo({
      url: '/pages/teacher/gl/gl'
    });
  },

  // 跳转到我的页
  goToMine() {
    const pages = getCurrentPages();
    const currentRoute = pages[pages.length - 1].route;
    if (currentRoute === 'pages/teacher/mine/mine') {
      return;
    }
  }
});