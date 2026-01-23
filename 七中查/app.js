App({
  // 全局数据（合并重复定义，保留所有必要字段）
  globalData: {
    isLogin: false,       // 是否已登录
    userInfo: null,       // 用户信息（id、username、role）
    token: null           // 登录凭证
  },

  // 小程序启动时执行：检查本地缓存的登录状态
  onLaunch() {
    // 从本地存储读取缓存的登录信息
    const storedUser = wx.getStorageSync('userInfo');
    const storedToken = wx.getStorageSync('token');

    if (storedUser && storedToken) {
      // 有缓存：恢复登录状态
      this.globalData.isLogin = true;
      this.globalData.userInfo = storedUser;
      this.globalData.token = storedToken;

      // 已登录则跳转到主页面（避免重复进入登录页）
      wx.switchTab({ url: '/pages/index/index' });
    } else {
      // 未登录：跳转到登录页
      wx.redirectTo({ url: '/pages/login/login' });
    }
  }
});