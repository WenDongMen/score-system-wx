FROM node:18-alpine
WORKDIR /app

# 复制依赖配置并安装
COPY package*.json ./
RUN npm install --production

# 复制所有项目代码
COPY . .

# 暴露端口
EXPOSE 3000

# 启动应用
CMD ["npm", "start"]
