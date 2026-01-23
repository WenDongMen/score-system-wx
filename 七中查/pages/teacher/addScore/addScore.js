Page({
  data: {
    studentName: '',    // 学生姓名（必填）
    studentId: '',      // 学生学号（必填）
    studentClass: '',   // 所属班级（选填）
    studentPhone: ''    // 联系电话（选填）
  },

  // 返回上一页（通常是主页面或教师功能页）
  goBack() {
    wx.navigateBack();
  },

  // 输入学生姓名
  onNameInput(e) {
    this.setData({ studentName: e.detail.value.trim() });
  },

  // 输入学生学号
  onIdInput(e) {
    this.setData({ studentId: e.detail.value.trim() });
  },

  // 输入所属班级
  onClassInput(e) {
    this.setData({ studentClass: e.detail.value.trim() });
  },

  // 输入联系电话
  onPhoneInput(e) {
    this.setData({ studentPhone: e.detail.value.trim() });
  },

  // 提交学生信息
  submitStudent() {
    const { studentName, studentId, studentClass, studentPhone } = this.data;
    
    // 1. 表单验证（必填项检查）
    if (!studentName) {
      wx.showToast({ title: '请输入学生姓名', icon: 'none' });
      return;
    }
    if (!studentId) {
      wx.showToast({ title: '请输入学生学号', icon: 'none' });
      return;
    }
    // 手机号格式验证（选填，有值时才校验）
    if (studentPhone && !/^1[3-9]\d{9}$/.test(studentPhone)) {
      wx.showToast({ title: '请输入有效的手机号', icon: 'none' });
      return;
    }

    // 2. 准备提交数据（格式与后端接口对齐，此处为示例结构）
    const studentData = {
      name: studentName,
      id: studentId,
      class: studentClass,
      phone: studentPhone,
      createTime: new Date().toISOString() // 创建时间
    };

    // 3. 调用接口提交（此处模拟请求，实际需替换为真实后端接口）
    const token = getApp().globalData.token; // 从全局获取登录凭证
    wx.showLoading({ title: '提交中...' });
    
    setTimeout(() => {
      wx.hideLoading();
      
      // 模拟提交成功：本地存储学生信息（实际项目中无需本地存储，接口返回成功即可）
      const existingStudents = wx.getStorageSync('studentList') || [];
      existingStudents.push(studentData);
      wx.setStorageSync('studentList', existingStudents);

      // 提示并返回上一页
      wx.showToast({ title: '学生添加成功', icon: 'success' });
      setTimeout(() => {
        wx.navigateBack();
      }, 1500);
    }, 1500);
  }
});