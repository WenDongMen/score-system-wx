Page({
  data: {
    currentExam: {},
    chart: null // 折线图实例
  },

  onLoad() {
    // 获取从上一页传递的考试数据
    const currentExam = wx.getStorageSync('currentExamData');
    if (!currentExam) {
      wx.navigateBack();
      return;
    }
    this.setData({ currentExam });
    // 初始化折线图
    this.initScoreChart(currentExam.historyScores);
  },

  // 初始化总分趋势折线图
  initScoreChart(historyScores) {
    const query = wx.createSelectorQuery().in(this);
    query.select('#scoreChart')
      .fields({ node: true, size: true })
      .exec((res) => {
        const canvas = res[0].node;
        const ctx = canvas.getContext('2d');
        const dpr = wx.getSystemInfoSync().pixelRatio;
        canvas.width = res[0].width * dpr;
        canvas.height = res[0].height * dpr;
        ctx.scale(dpr, dpr);

        // 处理图表数据
        const labels = historyScores.map(item => item.examDate);
        const data = historyScores.map(item => item.score);

        // 绘制折线图（简易版，也可使用echarts-for-weixin）
        this.drawLineChart(ctx, labels, data, res[0].width, res[0].height);
      });
  },

  // 手动绘制折线图（基础版）
  drawLineChart(ctx, labels, data, width, height) {
    const padding = 30;
    const chartWidth = width - 2 * padding;
    const chartHeight = height - 2 * padding;
    const maxValue = Math.max(...data) + 50;
    const minValue = Math.min(...data) - 50;
    const xStep = chartWidth / (labels.length - 1);
    const yStep = chartHeight / (maxValue - minValue);

    // 清空画布
    ctx.clearRect(0, 0, width, height);

    // 绘制坐标轴
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding);
    ctx.lineTo(width - padding, height - padding);
    ctx.strokeStyle = '#e5e5e5';
    ctx.stroke();

    // 绘制折线
    ctx.beginPath();
    data.forEach((value, index) => {
      const x = padding + index * xStep;
      const y = height - padding - (value - minValue) * yStep;
      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
      // 绘制数据点
      ctx.fillStyle = '#2f54eb';
      ctx.arc(x, y, 4, 0, 2 * Math.PI);
      ctx.fill();
    });
    ctx.strokeStyle = '#2f54eb';
    ctx.lineWidth = 2;
    ctx.stroke();

    // 绘制标签
    ctx.fillStyle = '#666';
    ctx.font = '12px sans-serif';
    labels.forEach((label, index) => {
      const x = padding + index * xStep;
      const y = height - padding + 15;
      ctx.textAlign = 'center';
      ctx.fillText(label, x, y);
    });
  },

  onUnload() {
    // 清除本地存储的考试数据
    wx.removeStorageSync('currentExamData');
  }
});