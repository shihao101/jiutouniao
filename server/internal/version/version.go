// Package version 版本单一事实源（修复：左上角版本号与实际不符）。
// 版本规则：修复级迭代递增末位（x.y.Z），遇十进一（z 满 10 进位到 y，y 满 10 进位到 x）。
package version

// App 当前版本号。每次发版（含 Bug 修复）必须递增，并同步补充 Web「更新记录」页。
const App = "6.0.0"
