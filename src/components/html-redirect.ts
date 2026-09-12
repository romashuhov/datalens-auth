const HTML_ESCAPE_MAP: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
};

export const escapeHtml = (value: string) =>
    value.replace(/[&<>"']/g, (char) => HTML_ESCAPE_MAP[char] ?? char);

const REDIRECT_LINK_ID = 'dl-redirect-link';

/**
 * A redirect page instead of a 302.
 *
 * The auth cookies are issued with `SameSite=Strict` by default, and browsers drop such cookies on
 * a request that continues a redirect chain started on another site (the identity provider).
 * A navigation started by this page is same-site, so the freshly set cookies are sent with it.
 *
 * The page is self contained: no external assets and no inline event handlers. The url is only
 * placed into html attributes (escaped), and the script reads it back from the link, so there is
 * no javascript string to escape. If inline scripts are blocked, the meta refresh still works, and
 * if both are blocked the user gets a plain link.
 */
export const renderHtmlRedirectPage = ({url, title}: {url: string; title: string}) => {
    const safeUrl = escapeHtml(url || '/');
    const safeTitle = escapeHtml(title);

    return [
        '<!doctype html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="utf-8">',
        `<meta http-equiv="refresh" content="0; url=${safeUrl}">`,
        '<meta name="robots" content="noindex">',
        `<title>${safeTitle}</title>`,
        '</head>',
        '<body>',
        `<a id="${REDIRECT_LINK_ID}" href="${safeUrl}">${safeTitle}</a>`,
        `<script>(function(){var l=document.getElementById(${JSON.stringify(
            REDIRECT_LINK_ID,
        )});if(l){window.location.replace(l.href);}})();</script>`,
        '</body>',
        '</html>',
        '',
    ].join('\n');
};
