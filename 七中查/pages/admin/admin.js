Page({
  data: {
    username: '',
    password: '',
    teachers: []
  },

  onLoad() {
    // 加载教师列表
    this.getTeachersList();
  },

  // 输入用户名
  onUsernameInput(e) {
    this.setData({ username: e.detail.value });
  },

  // 输入密码
  onPasswordInput(e) {
    this.setData({ password: e.detail.value });
  },

  // 获取教师列表
  getTeachersList() {
    const token = wx.getStorageSync('token');
    wx.request({
      url: 'http://8.149.242.96:5080/api/admin/teachers',
      method: 'GET',
      header: {
        'Authorization': 'Bearer ' + token
      },
      success: (res) => {
        if (res.data.code === 200) {
          this.setData({ teachers: res.data.data });
        } else {
          wx.showToast({ title: res.data.message, icon: 'none' });
        }
      },
      fail: () => {
        wx.showToast({ title: '网络错误', icon: 'none' });
      }
    });
  },

  // 新增教师
  addTeacher() {
    const { username, password } = this.data;
    if (!username || !password) {
      wx.showToast({ title: '用户名和密码不能为空', icon: 'none' });
      return;
    }

    const token = wx.getStorageSync('token');
    wx.request({
      url: 'http://8.149.242.96:5080/api/admin/teacher/add',
      method: 'POST',
      header: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      data: { username, password },
      success: (res) => {
        if (res.data.code === 200) {
          wx.showToast({ title: '添加成功', icon: 'success' });
          this.setData({ username: '', password: '' });
          this.getTeachersList(); // 刷新列表
        } else {
          wx.showToast({ title: res.data.message, icon: 'none' });
        }
      },
      fail: () => {
        wx.showToast({ title: '网络错误', icon: 'none' });
      }
    });
  },

  // 删除教师
  deleteTeacher(e) {
    const teacherId = e.currentTarget.dataset.id;
    wx.showModal({
      title: '提示',
      content: '确定要删除该教师吗？',
      success: (res) => {
        if (res.confirm) {
          const token = wx.getStorageSync('token');
          wx.request({
            url: `http://8.149.242.96:5080/api/admin/teacher/delete/${teacherId}`,
            method: 'DELETE',
            header: {
              'Authorization': 'Bearer ' + token
            },
            success: (res) => {
              if (res.data.code === 200) {
                wx.showToast({ title: '删除成功', icon: 'success' });
                this.getTeachersList(); // 刷新列表
              } else {
                wx.showToast({ title: res.data.message, icon: 'none' });
              }
            },
            fail: () => {
              wx.showToast({ title: '网络错误', icon: 'none' });
            }
          });
        }
      }
    });
  },
  goToManage() {
    wx.redirectTo({
      url: '/pages/admin/admin'
    });
  },

  // 跳转到我的页
  goToMine() {
    wx.redirectTo({
      url: '/pages/admin/mine/mine'
    });
  }
});