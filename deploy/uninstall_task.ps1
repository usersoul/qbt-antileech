$ErrorActionPreference = "SilentlyContinue"
Stop-ScheduledTask -TaskName "QBT-AntiLeech"
Unregister-ScheduledTask -TaskName "QBT-AntiLeech" -Confirm:$false
Write-Host "已停止并删除计划任务 QBT-AntiLeech"
Write-Host "注意：数据库中的封禁记录与 ipfilter.dat 仍然保留，如需清理请手动删除 data 目录"