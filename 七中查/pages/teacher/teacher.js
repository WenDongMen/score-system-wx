import wxCharts from '../../utils/wxcharts-min.js';

// 后端基础地址（统一管理）
const BASE_URL = 'http://192.168.101.114'; 

Page({
  data: {
    currentTab: 0, 
    searchKey: '',
    searchResult: [],
    // 初始化为空数组，不再硬编码
    subjectList: [], 
    studentList: [],
    chart: null
  },

  onLoad() {
    // 1. 校验token
    this.checkToken();
    // 2. 获取科目统计数据（异步）
    this.getSubjectStatistics().then(() => {
      // 3. 数据获取后再初始化图表（必须等数据加载完成）
      this.initChart();
    });
    // 4. 加载学生列表
    this.getStudentList();
  },

  // 新增：从后端获取科目成绩统计
  getSubjectStatistics() {
    return new Promise((resolve, reject) => {
      const token = wx.getStorageSync('token');
      if (!token) {
        wx.showToast({ title: '请先登录', icon: 'none' });
        reject();
        return;
      }

      wx.request({
        url: `${BASE_URL}/api/teacher/subject/statistics`,
        method: 'GET',
        header: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        success: (res) => {
          if (res.data.code === 200) {
            // 更新subjectList为数据库中的真实数据
            this.setData({ subjectList: res.data.data });
            resolve();
          } else {
            wx.showToast({ title: res.data.message || '获取统计数据失败', icon: 'none' });
            // 兜底：使用示例数据避免图表加载失败
            this.setData({
              subjectList: [
                { name: '语文', avgScore: 85, maxScore: 98 },
                { name: '数学', avgScore: 82, maxScore: 100 },
                { name: '英语', avgScore: 88, maxScore: 99 },
                { name: '物理', avgScore: 78, maxScore: 95 },
                { name: '化学', avgScore: 80, maxScore: 94 },
                { name: '生物', avgScore: 83, maxScore: 96 },
                { name: '历史', avgScore: 87, maxScore: 97 },
                { name: '地理', avgScore: 81, maxScore: 93 }
              ]
            });
            resolve();
          }
        },
        fail: () => {
          wx.showToast({ title: '网络错误，使用示例数据', icon: 'none' });
          // 兜底：使用示例数据
          this.setData({
            subjectList: [
              { name: '语文', avgScore: 85, maxScore: 98 },
              { name: '数学', avgScore: 82, maxScore: 100 },
              { name: '英语', avgScore: 88, maxScore: 99 },
              { name: '物理', avgScore: 78, maxScore: 95 },
              { name: '化学', avgScore: 80, maxScore: 94 },
              { name: '生物', avgScore: 83, maxScore: 96 },
              { name: '历史', avgScore: 87, maxScore: 97 },
              { name: '地理', avgScore: 81, maxScore: 93 }
            ]
          });
          resolve();
        }
      });
    });
  },

  // 原有方法：初始化图表（无需修改，因为subjectList已动态赋值）
  initChart() {
    const systemInfo = wx.getSystemInfoSync();
    const screenWidth = systemInfo.windowWidth - 20;

    const { subjectList } = this.data;
    const categories = subjectList.map(item => item.name);
    const avgScores = subjectList.map(item => item.avgScore);
    const maxScores = subjectList.map(item => item.maxScore);

    this.setData({
      chart: new wxCharts({
        canvasId: 'scoreChart',
        type: 'line',
        categories: categories,
        series: [
          {
            name: '班级平均分',
            data: avgScores,
            color: '#1677ff',
            format: (val) => val + '分'
          },
          {
            name: '班级最高分',
            data: maxScores,
            color: '#ff4d4f',
            format: (val) => val + '分'
          }
        ],
        yAxis: {
          min: 0,
          max: 100,
          title: '分数'
        },
        xAxis: {
          disableGrid: false,
          type: 'calibration'
        },
        width: screenWidth,
        height: 200,
        dataLabel: true,
        legend: true,
        background: '#f5f5f5'
      })
    });
  },

  //Token校验（跳转到登录页）
  checkToken() {
    const token = wx.getStorageSync('token');
    if (!token) {
      wx.redirectTo({ url: '/pages/login/login' });
    }
  },

  switchTab(e) {
    const index = e.currentTarget.dataset.index;
    this.setData({ currentTab: index });
    if (index === 1) {
      this.getStudentList();
    }
  },

  onSearchInput(e) {
    this.setData({ searchKey: e.detail.value });
  },

  searchStudent() {
    const { searchKey } = this.data;
    if (!searchKey) {
      wx.showToast({ title: '请输入搜索内容', icon: 'none' });
      return;
    }

    const token = wx.getStorageSync('token');
    wx.request({
      url: `${BASE_URL}/api/teacher/student/search`,
      method: 'GET',
      header: { Authorization: `Bearer ${token}` },
      data: { keyword: searchKey },
      success: (res) => {
        if (res.data.code === 200) {
          this.setData({ searchResult: res.data.data });
        } else {
          wx.showToast({ title: res.data.message || '搜索失败', icon: 'none' });
        }
      },
      fail: () => {
        wx.showToast({ title: '网络错误', icon: 'none' });
      }
    });
  },

  showStudentScore(e) {
    const studentId = e.currentTarget.dataset.id;
    wx.navigateTo({
      url: `/pages/teacher/studentScore/studentScore?id=${studentId}`
    });
  },

  getStudentList() {
    const token = wx.getStorageSync('token');
    wx.request({
      url: `${BASE_URL}/api/teacher/student/list`,
      method: 'GET',
      header: { Authorization: `Bearer ${token}` },
      success: (res) => {
        if (res.data.code === 200) {
          this.setData({ studentList: res.data.data });
        } else {
          wx.showToast({ title: res.data.message || '加载失败', icon: 'none' });
        }
      },
      fail: () => {
        wx.showToast({ title: '加载学生列表失败', icon: 'none' });
      }
    });
  },

  goToAddStudent() {
    wx.navigateTo({ url: '/pages/teacher/addStudent/addStudent' });
  },

  goToAddScore() {
    wx.navigateTo({ url: '/pages/teacher/addScore/addScore' });
  },

  goToManage() {
    wx.navigateTo({ url: '/pages/teacher/gl/gl' });
  },

  goToMine() {
    wx.navigateTo({ url: '/pages/teacher/mine/mine' });
  },

  goToEditStudent(e) {
    const id = e.currentTarget.dataset.id;
    wx.navigateTo({ url: `/pages/teacher/editStudent/editStudent?id=${id}` });
  },

  goToEditScore(e) {
    const id = e.currentTarget.dataset.id;
    wx.navigateTo({ url: `/pages/teacher/editScore/editScore?id=${id}` });
  }
});