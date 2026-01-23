Page({
  data: {
    isSubmitting: false,
    form: {
      username: '',
      idCard: '',
      studentId: ''
    },
    errors: {}
  },

  onLoad(options) {
    if (!options.id) {
      wx.showToast({ title: '参数错误', icon: 'none' });
      setTimeout(() => wx.navigateBack(), 1000);
      return;
    }
    this.setData({ 'form.studentId': options.id });
    this.getStudentDetail(options.id);
  },

  // 返回上一页
  onNavigateBack() {
    wx.navigateBack();
  },

  // 获取学生详情
  getStudentDetail(id) {
    const token = wx.getStorageSync("token");
    wx.showLoading({ title: '加载中...' });
    wx.request({
      url: `http://192.168.101.114:5080/api/teacher/student/${id}`,
      method: "GET",
      header: { "Authorization": `Bearer ${token}` },
      success: (res) => {
        wx.hideLoading();
        if (res.data.code === 200) {
          this.setData({
            form: {
              username: res.data.data.username || '',
              idCard: res.data.data.id_card || '',
              studentId: id
            }
          });
        } else {
          wx.showToast({ title: res.data.msg, icon: 'none' });
        }
      },
      fail: () => {
        wx.hideLoading();
        wx.showToast({ title: '网络错误', icon: 'none' });
      }
    });
  },

  // 输入框绑定
  handleInput(e) {
    const { name, value } = e.detail;
    this.setData({ 
      [`form.${name}`]: value,
      [`errors.${name}`]: '' // 清空错误提示
    });
  },

  // 表单验证
  validateForm() {
    const { username, idCard } = this.data.form;
    const errors = {};
    if (!username.trim()) {
      errors.username = '请输入学生姓名';
    }
    if (!idCard.trim()) {
      errors.idCard = '请输入身份证号';
    } else if (idCard.length !== 18) {
      errors.idCard = '身份证号必须为18位';
    }
    this.setData({ errors });
    return Object.keys(errors).length === 0;
  },

  // 提交修改
  handleSubmit() {
    if (!this.validateForm()) return;

    const { username, idCard, studentId } = this.data.form;
    this.setData({ isSubmitting: true });

    const token = wx.getStorageSync("token");
    wx.request({
      url: `http://8.149.242.96:5080/api/teacher/student/${studentId}`,
      method: "PUT",
      header: { "Authorization": `Bearer ${token}` },
      data: { username: username.trim(), id_card: idCard.trim() },
      success: (res) => {
        if (res.data.code === 200) {
          wx.showToast({ title: '修改成功' });
          setTimeout(() => wx.navigateBack(), 1500);
        } else {
          wx.showToast({ title: res.data.msg, icon: 'none' });
        }
      },
      fail: () => {
        wx.showToast({ title: '网络错误', icon: 'none' });
      },
      complete: () => {
        this.setData({ isSubmitting: false });
      }
    });
  }
});