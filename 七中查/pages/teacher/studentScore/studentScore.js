import wxCharts from '../../utils/wxcharts-min.js';

Page({
  data: {
    studentId: '',
    studentName: '',
    scoreList: []
  },

  onLoad(options) {
    if (!options.id) {
      wx.showToast({ title: '参数错误', icon: 'none' });
      setTimeout(() => wx.navigateBack(), 1000);
      return;
    }
    this.setData({ studentId: options.id });
    this.getStudentScore(options.id);
  },

  // 返回上一页
  onNavigateBack() {
    wx.navigateBack();
  },

  // 获取学生成绩
  getStudentScore(id) {
    const token = wx.getStorageSync("token");
    wx.showLoading({ title: '加载中...' });
    wx.request({
      url: `http://192.168.101.114:5080/api/teacher/student/score/${id}`,
      method: "GET",
      header: { "Authorization": `Bearer ${token}` },
      success: (res) => {
        wx.hideLoading();
        if (res.data.code === 200) {
          const scoreList = res.data.data || [];
          this.setData({
            studentName: res.data.studentName || '未知学生',
            scoreList: scoreList.map(item => ({
              subject: item.subject,
              score: item.score,
              examDate: item.exam_date || '未知'
            }))
          });
          this.initStudentChart(scoreList);
        }
      },
      fail: () => {
        wx.hideLoading();
        wx.showToast({ title: '加载失败', icon: 'none' });
      }
    });
  },

  // 初始化学生成绩折线图
  initStudentChart(scoreList) {
    const systemInfo = wx.getSystemInfoSync();
    const screenWidth = systemInfo.windowWidth - 20;

    const categories = scoreList.map(item => item.subject);
    const scores = scoreList.map(item => item.score);

    new wxCharts({
      canvasId: 'studentScoreChart',
      type: 'line',
      categories: categories,
      series: [
        {
          name: '我的成绩',
          data: scores,
          color: '#1677ff',
          format: (val) => val + '分'
        }
      ],
      yAxis: {
        min: 0,
        max: 100,
        title: '分数'
      },
      xAxis: {
        disableGrid: false
      },
      width: screenWidth,
      height: 200,
      dataLabel: true,
      legend: false,
      background: '#f5f5f5'
    });
  }
});