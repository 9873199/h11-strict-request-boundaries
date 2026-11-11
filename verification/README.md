独立验收说明

冻结提交：https://github.com/9873199/h11-strict-request-boundaries/commit/5222fdd2b0d809f5e3a9ca1bb9d6ef1c63e7a4c5
实际解释器：3.14.3 (tags/v3.14.3:323c59a, Feb  3 2026, 16:04:56) [MSC v.1944 64 bit (AMD64)]

使用冻结提交与environment-reviewed.json解释器。acceptance-r1保留149项全部库回归和独立33项（31过2失败），两项失败是同一BWS兼容问题。position-r1对四种坏边界遍历每个切点，连同有限EOF检查共5项通过。controls-r2的9项有效补测全过；controls-r1的额外默认分号前BWS假设失败，在initial-bws-r1未改初始Git源码上同样失败，不能扣模型分。初始源码由确切initial_sha的git archive回放，command.json保留命令与archive SHA，source.zip只留缓存。format-reference-r1提供RFC9112原文；r2补RFC9110第5.6.3节并纠正BWS接收规则的出处归属，不修改旧proof。模型原轨中最终149通过与独立回归分开；原轨71新增用例把一个合法BWS写法误列坏输入，故不能用原生通过率证明标准全覆盖。视频为独立验证控制台，4条命令退出0/1/0/0，失败没有剪掉。全部协议输入在内存，未连接真实代理、未改变原轨或产物。

每组目录内的 *-command.json 保留真实参数、工作目录、PYTHONPATH、退出码和原始日志位置；test-results.json 与 JUnit XML 保留完整成绩。跨机器运行时把这些绝对路径映射到同一冻结 checkout 和自己的缓存目录，所有 --basetemp、XML 和构建输出均放在缓存里。依赖版本见 environment-reviewed.json。
这些材料在模型单轮结束后生成，与原轨内测试分开，不代表项目方质检通过。原轨和视频只放各自的飞书附件。


冻结产物提交：https://github.com/9873199/h11-strict-request-boundaries/commit/5222fdd2b0d809f5e3a9ca1bb9d6ef1c63e7a4c5
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
