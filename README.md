# Windows 双击启动后未打开网页的处理方法

双击 `Start-Windows.cmd` 后，如果命令窗口关闭但没有打开网页，可按以下步骤打开作品。

1. 进入解压后的“支撑材料 → 作品源码 → BindCart”文件夹，也就是 `Start-Windows.cmd` 所在的文件夹。

2. 点击文件资源管理器顶部的**地址栏**，输入 `cmd`，按回车。

3. 将下面的命令完整复制到打开的窗口中，按回车：

   ```bat
   powershell.exe -NoProfile -Command "Start-Process ((Get-Content -Raw 'app\var\dual-runtime.json' | ConvertFrom-Json).url -replace '/demo/', '/intro/')"
   ```

4. 浏览器打开介绍页后，点击 **“进入交互演示”**。

如果提示找不到 `dual-runtime.json`，请确认命令窗口位于 `Start-Windows.cmd` 所在的文件夹，然后在同一个窗口中执行：

```bat
Start-Windows.cmd
```

看到 `Ready: http://127.0.0.1:…/intro/` 后，再执行第 3 步的命令。
