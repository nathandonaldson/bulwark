// Root app — page routing.
// Tweaks panel removed per ADR-020. Single shipped layout: tabs nav, Inter font, radial Shield.

function App() {
  const store = useStore();
  const [page, setPage] = React.useState('shield');

  const gotoPage = (p, focus) => {
    setPage(p);
    if (focus) window.dispatchEvent(new CustomEvent('bulwark:focus', {detail: focus}));
  };

  React.useEffect(() => {
    const h = (e) => gotoPage(e.detail.page, e.detail.focus);
    window.addEventListener('bulwark:goto', h);
    return () => window.removeEventListener('bulwark:goto', h);
  }, []);

  return (
    <div className="app">
      <TopNav page={page} setPage={setPage} store={store} />
      <main style={{overflow: 'auto'}}>
        {page === 'shield'         && <PageShield store={store} />}
        {page === 'events'         && <PageEvents store={store} />}
        {page === 'configure'      && <PageConfigure store={store} />}
        {page === 'leak-detection' && <PageLeakDetection store={store} />}
        {page === 'test'           && <PageTest store={store} />}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
