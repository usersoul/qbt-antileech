@echo off
chcp 65001 >nul
cd /d "%~dp0.."
if not exist config.json (
  echo [错误] 缺少 config.json，请先复制 config.example.json 并填写 WebUI 账号密码
  pause
  exit /b 1
)
echo 正在前台运行 qBittorrent 反吸血系统，Ctrl+C 停止...
python -m antileech run -c config.json
pause