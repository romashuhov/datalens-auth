import {escapeHtml, renderHtmlRedirectPage} from './html-redirect';

describe('escapeHtml', () => {
    test('escapes every html sensitive character', () => {
        expect(escapeHtml(`&<>"'`)).toBe('&amp;&lt;&gt;&quot;&#39;');
    });

    test('keeps a plain url as is', () => {
        expect(escapeHtml('https://datalens.example.com/')).toBe('https://datalens.example.com/');
    });

    test('escapes query separators of a url', () => {
        expect(escapeHtml('https://example.com/?a=1&b=2')).toBe('https://example.com/?a=1&amp;b=2');
    });
});

describe('renderHtmlRedirectPage', () => {
    test('renders a meta refresh, a link and a script for the url', () => {
        const page = renderHtmlRedirectPage({
            url: 'https://datalens.example.com/',
            title: 'Continue',
        });

        expect(page).toContain(
            '<meta http-equiv="refresh" content="0; url=https://datalens.example.com/">',
        );
        expect(page).toContain(
            '<a id="dl-redirect-link" href="https://datalens.example.com/">Continue</a>',
        );
        expect(page).toContain('window.location.replace(l.href)');
    });

    test('falls back to the root url', () => {
        expect(renderHtmlRedirectPage({url: '', title: 'Continue'})).toContain(
            '<a id="dl-redirect-link" href="/">Continue</a>',
        );
    });

    test('does not let a crafted url break out of the attribute or the script', () => {
        const page = renderHtmlRedirectPage({
            url: '/"><script>alert(1)</script>',
            title: 'Continue',
        });

        expect(page).not.toContain('<script>alert(1)');
        expect(page).toContain('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
    });
});
