param(
    [string]$ProjectDir = "C:\qbt-antileech",
    [string]$Python = "",
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"

if (-not $Python) {
    $cmd = Get-Command pythonw.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "未找到 pythonw.exe，请先安装 Python 3.10+ 并加入 PATH，或用 -Python 指定完整路径" }
    $Python = $cmd.Source
}
if (-not $Config) { $Config = Join-Path $ProjectDir "config.json" }
if (-not (Test-Path $Config)) { throw "配置文件不存在: $Config" }

Write-Host "Python : $Python"
Write-Host "项目   : $ProjectDir"
Write-Host "配置   : $Config"

$action = New-ScheduledTaskAction -Execute $Python `
    -Argument "-m antileech run -c `"$Config`"" `
    -WorkingDirectory $ProjectDir

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "QBT-AntiLeech" `
    -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description "qBittorrent 自动反吸血守护进程" -Force | Out-Null

Write-Host "已注册计划任务 QBT-AntiLeech（开机自启，SYSTEM 权限，崩溃后 1 分钟自动重启）"
Write-Host "启动: Start-ScheduledTask -TaskName QBT-AntiLeech"
Write-Host "查看: Get-ScheduledTaskInfo -TaskName QBT-AntiLeech"