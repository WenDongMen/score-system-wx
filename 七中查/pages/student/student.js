Page({
  data: {
    userInfo: {},
    examList: [], // 按考试日期分组的成绩列表
    errorMsg: "",
    isLoading: false // 新增加载状态初始化
  },

  onLoad() {
    this.getLocalUserInfo();
    this.getStudentScores();
  },

  getLocalUserInfo() {
    const storedUser = wx.getStorageSync('userInfo');
    if (storedUser && storedUser.username) {
      this.setData({ userInfo: storedUser });
    } else {
      wx.redirectTo({ url: '/pages/login/login' });
    }
  },

  formatIdCard(idCard) {
    if (!idCard || idCard.length !== 18) return '未绑定';
    return idCard.slice(0, 6) + '********' + idCard.slice(14);
  },

  // 重构成绩请求：按考试日期分组
  getStudentScores() {
    if (this.data.isLoading) return; // 防止重复请求
    this.setData({ isLoading: true, errorMsg: "" });

    const token = wx.getStorageSync('token');
    if (!token) {
      wx.redirectTo({ url: '/pages/login/login' });
      return;
    }

    wx.request({
      url: 'http://8.149.242.96:5080/api/student/score/my',
      method: 'POST',
      timeout: 10000,
      header: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },

      success: (res) => {
        console.log('成绩接口返回：', res.data);
        const resp = res.data || {};

        if (res.statusCode === 200 && resp.code === 200 && resp.data) {
          // 处理数据：按考试日期分组
          const examGroup = this.groupScoresByExamDate(resp.data);
          this.setData({ examList: examGroup });
        } else {
          console.error("接口错误：", resp);
          this.setData({
            errorMsg: resp.message || "查询成绩失败，请稍后再试"
          });
        }
      },

      fail: (err) => {
        console.error("请求失败：", err);
        let e = "网络连接失败，请检查服务器";

        if (err.errMsg.includes("timeout")) e = "请求超时，请检查后端服务是否运行";
        if (err.errMsg.includes("connect")) e = "无法连接服务器，请检查 IP 和端口";

        this.setData({ errorMsg: e });
      },

      complete: () => {
        this.setData({ isLoading: false });
      }
    });
  },

  // 按考试日期分组处理成绩数据
  groupScoresByExamDate(scoreData) {
    const { subjects = [] } = scoreData;
    // 按考试日期分组
    const dateMap = new Map();
    subjects.forEach(item => {
      const examDate = item.exam_date || item.考试日期 || '未知日期';
      if (!dateMap.has(examDate)) {
        dateMap.set(examDate, {
          examDate: examDate,
          totalScore: 0,
          gradeRank: 0, // 级部排名（需后端返回，这里先模拟）
          classRank: 0, // 班级排名（需后端返回，这里先模拟）
          subjects: []
        });
      }
      const group = dateMap.get(examDate);
      group.subjects.push({
        subject: item.subject || item.科目,
        score: Number(item.score || item.分数 || 0),
        examDate: examDate,
        isGradeTopTen: item.is_grade_top_ten || false // 级部前十标记（需后端返回）
      });
      // 计算该次考试总分（若后端已返回可直接用）
      group.totalScore = group.subjects.reduce((sum, sub) => sum + sub.score, 0);
      // 模拟排名（实际需从后端获取）
      group.gradeRank = Math.floor(Math.random() * 100) + 1;
      group.classRank = Math.floor(Math.random() * 20) + 1;
    });

    // 转换为数组并按考试日期倒序排列
    const examList = Array.from(dateMap.values()).sort((a, b) => {
      return new Date(b.examDate) - new Date(a.examDate);
    });
    return examList;
  },

  // 跳转至考试详情页
  goToExamDetail(e) {
    const examDate = e.currentTarget.dataset.examdate;
    // 找到对应考试的数据
    const currentExam = this.data.examList.find(item => item.examDate === examDate);
    if (!currentExam) return;

    // 处理排名变化（模拟，实际需后端返回两次考试的排名对比）
    const lastRank = currentExam.gradeRank + Math.floor(Math.random() * 10) - 5;
    const rankChange = currentExam.gradeRank - lastRank;
    let rankChangeType = 'same';
    let rankChangeDesc = '排名不变';
    if (rankChange < 0) {
      rankChangeType = 'up';
      rankChangeDesc = `进步${Math.abs(rankChange)}名`;
    } else if (rankChange > 0) {
      rankChangeType = 'down';
      rankChangeDesc = `退步${rankChange}名`;
    }

    // 存储当前考试数据到本地，供详情页使用
    wx.setStorageSync('currentExamData', {
      ...currentExam,
      rankChangeType,
      rankChangeDesc,
      // 模拟历史总分数据（用于折线图）
      historyScores: [
        { examDate: '25.11.01', score: Math.floor(Math.random() * 100) + 500 },
        { examDate: '25.11.15', score: Math.floor(Math.random() * 100) + 500 },
        { examDate: currentExam.examDate, score: currentExam.totalScore }
      ]
    });

    // 跳转详情页
    wx.navigateTo({
      url: '/pages/student/scoreDetail/scoreDetail'
    });
  },

  reloadScores() {
    this.getStudentScores();
  },

  onShow() {
    const token = wx.getStorageSync('token');
    const user = wx.getStorageSync('userInfo');
    if (!token || !user?.username) return;
  }
});