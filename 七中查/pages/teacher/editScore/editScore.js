Page({
  data: {
    isSubmitting: false,
    studentId: '',
    studentName: '',
    subjects: ['语文', '数学', '英语', '物理', '化学', '生物', '历史', '地理'],
    subjectIndex: 0,
    form: {
      score: '',
      examDate: ''
    },
    errors: {}
  },

  onLoad(options) {
    if (!options.id) {
      wx.showToast({ title: '参数错误', icon: 'none' });
      setTimeout(() => wx.navigateBack(), 1000);
      return;
    }
    this.setData({ 
      studentId: options.id,
      'form.examDate': new Date().toISOString().split('T')[0] // 默认当前日期
    });
    this.getStudentDetail(options.id);
    this.getStudentScore(options.id);
  },

  // 返回上一页
  onNavigateBack() {
    wx.navigateBack();
  },

  // 获取学生详情
  getStudentDetail(id) {
    const token = wx.getStorageSync("token");
    wx.request({
      url: `http://8.149.242.96:5080/api/teacher/student/${id}`,
      method: "GET",
      header: { "Authorization": `Bearer ${token}` },
      success: (res) => {
        if (res.data.code === 200) {
          this.setData({ studentName: res.data.data.username });
        }
      }
    });
  },

  // 获取学生当前成绩
  getStudentScore(id) {
    const token = wx.getStorageSync("token");
    wx.request({
      url: `http://8.149.242.96:5080/api/teacher/student/score/${id}`,
      method: "GET",
      header: { "Authorization": `Bearer ${token}` },
      success: (res) => {
        if (res.data.code === 200 && res.data.data) {
          this.setData({
            'form.score': res.data.data.score || '',
            'form.examDate': res.data.data.exam_date || new Date().toISOString().split('T')[0],
            subjectIndex: this.data.subjects.indexOf(res.data.data.subject) || 0
          });
        }
      }
    });
  },

  // 科目选择
  onSubjectChange(e) {
    this.setData({ subjectIndex: e.detail.value });
  },

  // 日期选择
  onDateChange(e) {
    this.setData({ 'form.examDate': e.detail.value });
  },

  // 分数输入
  handleInput(e) {
    this.setData({ 
      'form.score': e.detail.value,
      'errors.score': ''
    });
  },

  // 表单验证
  validateForm() {
    const { score } = this.data.form;
    const errors = {};
    if (!score) {
      errors.score = '请输入分数';
    } else if (score < 0 || score > 100) {
      errors.score = '分数必须在0-100之间';
    }
    this.setData({ errors });
    return Object.keys(errors).length === 0;
  },

  // 提交修改
  handleSubmit() {
    if (!this.validateForm()) return;

    const { studentId, subjectIndex, subjects, form } = this.data;
    const submitData = {
      student_id: studentId,
      subject: subjects[subjectIndex],
      score: Number(form.score),
      exam_date: form.examDate
    };

    this.setData({ isSubmitting: true });
    const token = wx.getStorageSync("token");
    wx.request({
      url: `http://8.149.242.96:5080/api/teacher/student/score/${studentId}`,
      method: "PUT",
      header: { "Authorization": `Bearer ${token}` },
      data: submitData,
      success: (res) => {
        if (res.data.code === 200) {
          wx.showToast({ title: '成绩修改成功' });
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