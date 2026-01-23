// 考试详情页 JS
import * as echarts from '../../ec-canvas/echarts';

Page({
  data: {
    ec: {
      lazyLoad: true // 延迟加载图表
    },
    currentExam: {},
    subjectHistory: []
  },

  onLoad() {
    // 1. 获取考试数据和单科历史成绩
    const currentExam = wx.getStorageSync('currentExamData');
    const subjectHistory = wx.getStorageSync('subjectHistory');
    this.setData({ currentExam, subjectHistory });

    // 2. 初始化折线图
    this.initSubjectChart();
  },

  // 初始化单科成绩折线图
  initSubjectChart() {
    this.selectComponent('#subjectChart').init((canvas, width, height, dpr) => {
      const chart = echarts.init(canvas, null, {
        width: width,
        height: height,
        devicePixelRatio: dpr
      });

      // 处理图表数据
      const examDates = []; // x轴：所有考试日期（去重排序）
      const series = [];    // 系列：每科的成绩数据

      // 第一步：收集所有考试日期
      const dateSet = new Set();
      this.data.subjectHistory.forEach(subject => {
        subject.history.forEach(item => dateSet.add(item.exam_date));
      });
      examDates.push(...Array.from(dateSet).sort((a, b) => new Date(a) - new Date(b)));

      // 第二步：按科目生成系列数据
      this.data.subjectHistory.forEach(subject => {
        const scoreData = [];
        // 按考试日期匹配分数（无成绩则补0或空）
        examDates.forEach(date => {
          const item = subject.history.find(i => i.exam_date === date);
          scoreData.push(item ? item.score : null);
        });
        series.push({
          name: subject.subject,
          type: 'line',
          data: scoreData,
          symbol: 'circle',
          symbolSize: 8
        });
      });

      // 图表配置
      const option = {
        tooltip: {
          trigger: 'axis',
          formatter: '{b}<br/>{a}: {c}分'
        },
        legend: {
          data: this.data.subjectHistory.map(s => s.subject),
          top: 10
        },
        xAxis: {
          type: 'category',
          data: examDates,
          axisLabel: {
            rotate: 30,
            interval: 0
          }
        },
        yAxis: {
          type: 'value',
          min: 0,
          max: 100,
          axisLabel: {
            formatter: '{value}分'
          }
        },
        series: series
      };

      chart.setOption(option);
      return chart;
    });
  }
});