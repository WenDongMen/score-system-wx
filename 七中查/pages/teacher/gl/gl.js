// pages/teacher/gl/gl.js
Page({

  /**
   * 页面的初始数据
   */
  data: {

  },

  /**
   * 生命周期函数--监听页面加载
   */
  onLoad(options) {

  },

  /**
   * 生命周期函数--监听页面初次渲染完成
   */
  onReady() {

  },

  /**
   * 生命周期函数--监听页面显示
   */
  onShow() {

  },

  /**
   * 生命周期函数--监听页面隐藏
   */
  onHide() {

  },

  /**
   * 生命周期函数--监听页面卸载
   */
  onUnload() {

  },

  /**
   * 页面相关事件处理函数--监听用户下拉动作
   */
  onPullDownRefresh() {

  },

  /**
   * 页面上拉触底事件的处理函数
   */
  onReachBottom() {

  },

  /**
   * 用户点击右上角分享
   */
  onShareAppMessage() {

  },
  goToQuery() {
    // 避免重复跳转：判断当前是否已是查询页eturn;
    wx.redirectTo({
      url: '/pages/teacher/teacher'
    });
  },

  // 跳转到管理页
  goToManage() {
    const pages = getCurrentPages();
    const currentRoute = pages[pages.length - 1].route;
    if (currentRoute === 'pages/teacher/gl/gl') {
      return;
    }
  },

  // 跳转到我的页
  goToMine() {
    wx.redirectTo({
      url: '/pages/teacher/mine/mine'
    });
  }
})