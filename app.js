/* ==========================================================================
   TP 安全课堂 · 存储策略自检交互控制台 (Zero Emoji / Pure SVG)
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  initScrollProgress();
  initPlayground();
});

// 阅读进度监听
function initScrollProgress() {
  const progressBar = document.getElementById('readProgress');
  window.addEventListener('scroll', () => {
    const totalHeight = document.documentElement.scrollHeight - window.innerHeight;
    const progress = (window.pageYOffset / totalHeight) * 100;
    if (progressBar) {
      progressBar.style.width = `${progress}%`;
    }
  });
}

// 存储桶策略安全检测数据
const policyDatabase = {
  vulnerable: {
    title: "漏洞现状：全公开 ListBucket + GetObject",
    badgeType: "alert",
    badgeLabel: "高危策略 (Critical)",
    iamPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicAllAccess",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket" // [CRITICAL] 致命错误：允许任何人枚举整个目录
      ],
      "Resource": [
        "arn:aws:s3:::s.lovestatic.com",
        "arn:aws:s3:::s.lovestatic.com/*"
      ]
    }
  ]
}`,
    attackSimulation: `[GET] /?list-type=2&prefix=img/origin/vip/10038461/ HTTP/1.1
Host: s.lovestatic.com

<-- HTTP/1.1 200 OK
<-- Content-Type: application/xml
<-- <ListBucketResult>
<--   <Key>img/origin/vip/10038461/01183527...jpg</Key>
<--   <Key>img/origin/vip/10038461/0167d681...jpg</Key>
<--   ... (101 个真实哈希全部返回！)

[EXPLOIT SUCCESS] 攻击者 1 秒内拿到全部 101 张 VIP 大图哈希，应用层限制被完全穿透！`,
    verdict: "全线溃败：虽然应用层有严格的 isVip 校验，但存储层直接泄露了目录账本。"
  },

  hardened_getonly: {
    title: "方案 A：关闭 ListBucket，保留公共 GetObject",
    badgeType: "warn",
    badgeLabel: "治标不治本 (Half-Secured)",
    iamPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicGetOnly",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject", // [SECURED] 禁止了 ListBucket
      "Resource": "arn:aws:s3:::s.lovestatic.com/*"
    }
  ]
}`,
    attackSimulation: `[GET] /?list-type=2&prefix=img/origin/vip/10038461/ HTTP/1.1
Host: s.lovestatic.com

<-- HTTP/1.1 403 Forbidden
<-- <Error><Code>AccessDenied</Code></Error>

[GET] /img/origin/vip/10038461/01183527...jpg HTTP/1.1
<-- HTTP/1.1 200 OK (若攻击者通过其他途径拿到一个文件名，仍可直接下载)

[WARNING] S3 目录遍历被成功阻断。但本质上依然依赖“哈希不可预测性（Security through Obscurity）”。若文件名因缓存、日志或二次泄露，依然无鉴权。`,
    verdict: "部分缓解：阻断了批量自动化枚举，但对象本身依然无鉴权直连。"
  },

  presigned_secure: {
    title: "方案 B：私有存储桶 + 短效预签名机制 (Zero Trust 工业标准)",
    badgeType: "highlight",
    badgeLabel: "坚不可摧 (Zero Trust Production)",
    iamPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AppBackendFullAccessOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/BackendAppRole"
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::secure-vault",
        "arn:aws:s3:::secure-vault/*"
      ]
    }
    // 匿名用户默认全部 Deny
  ]
}`,
    attackSimulation: `[GET] /?list-type=2&prefix=img/origin/vip/10038461/ HTTP/1.1
<-- HTTP/1.1 403 Forbidden (AccessDenied)

[GET] /img/origin/vip/10038461/01183527...jpg HTTP/1.1
<-- HTTP/1.1 403 Forbidden (无有效签名一律拒绝)

[GET] /img/...jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=VALID (VIP用户)
<-- HTTP/1.1 200 OK (仅在 15 分钟内有效)

[ZERO TRUST SECURED] 存储层与应用层实现完全的“零信任协同”。未通过后端 VIP 校验的用户，既无法列出文件，也无法直接下载任何单张图片。`,
    verdict: "黄金防御：存储层私有化 + 动态时效签名，实现真正的双层纵深防御。"
  }
};

// 交互式检测台渲染逻辑
function initPlayground() {
  const tabs = document.querySelectorAll('.pg-tab');
  const container = document.getElementById('pgContent');

  function render(policyKey) {
    const data = policyDatabase[policyKey];
    if (!data || !container) return;

    container.innerHTML = `
      <div class="pg-result-grid">
        <div class="pg-panel">
          <div class="pg-panel-title">
            <svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <span>S3 Bucket IAM Policy (存储桶策略)</span>
            <span class="tag ${data.badgeType}">${data.badgeLabel}</span>
          </div>
          <div class="pg-code-preview">
            <pre><code>${escapeHtml(data.iamPolicy)}</code></pre>
          </div>
        </div>

        <div class="pg-panel">
          <div class="pg-panel-title">
            <svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="14.5 17.5 3 6 3 3 6 3 17.5 14.5"></polyline><line x1="13" y1="19" x2="19" y2="13"></line><line x1="16" y1="16" x2="20" y2="20"></line><line x1="19" y1="21" x2="21" y2="19"></line><polyline points="14.5 6.5 18 3 21 3 21 6 17.5 9.5"></polyline><line x1="5" y1="14" x2="9" y2="18"></line><line x1="7" y1="17" x2="3" y2="21"></line><line x1="3" y1="19" x2="5" y2="21"></line></svg>
            <span>攻击者请求与响应实时模拟测试</span>
          </div>
          <div class="pg-code-preview">
            <pre><code>${escapeHtml(data.attackSimulation)}</code></pre>
          </div>
        </div>
      </div>
      <div class="status-badge ${policyKey === 'presigned_secure' ? 'success-badge' : 'warning-callout'}" style="margin-top: 18px;">
        <svg class="ui-icon inline-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        <strong>综合评估：</strong> ${data.verdict}
      </div>
    `;
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const policyKey = tab.getAttribute('data-policy');
      render(policyKey);
    });
  });

  // 默认加载漏洞策略
  render('vulnerable');
}

function escapeHtml(string) {
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
