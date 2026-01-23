Page({
  data: {
    form: {
      username: '',
      idCard: ''
    },
    errors: {},
    isSubmitting: false
  },

  // 输入框绑定
  handleInput(e) {
    const { name, value } = e.detail;
    this.setData({ [`form.${name}`]: value });
  },

  // 提交学生信息
  handleSubmit(e) {
    const { username, idCard } = this.data.form;
    const token = wx.getStorageSync("token");
    const errors = { username: '', idCard: '' };
    let hasError = false;

    // 前端校验
    if (!username) {
      errors.username = "请输入学生姓名";
      hasError = true;
    }
    if (!idCard) {
      errors.idCard = "请输入身份证号";
      hasError = true;
    } else if (!/^\d{17}[\dXx]$/.test(idCard)) {
      errors.idCard = "请输入18位有效身份证号";
      hasError = true;
    }

    if (hasError) {
      this.setData({ errors });
      return;
    }

    this.setData({ isSubmitting: true });
    wx.request({
      url: "http://8.149.242.96:5080/api/teacher/student/add",
      method: "POST",
      header: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      data: { username, id_card: idCard },
      success: (res) => {
        const { code, message } = res.data;
        if (code === 200) {
          wx.showToast({ title: message, icon: 'success' });
          setTimeout(() => {
            wx.navigateBack({
              success: () => {
                const pages = getCurrentPages();
                const teacherPage = pages[pages.length - 1];
                teacherPage.getStudentList(); // 刷新学生列表
              }
            });
          }, 1500);
        } else {
          wx.showToast({ title: message || "添加失败", icon: "none" });
        }
      },
      fail: () => {
        wx.showToast({ title: "网络错误，请检查连接", icon: "none" });
      },
      complete: () => {
        this.setData({ isSubmitting: false });
      }
    });
  },

  // 返回上一页
  onNavigateBack() {
    wx.navigateBack();
  }
});