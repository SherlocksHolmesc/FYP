(function () {
  const eth = window.ethereum;
  if (!eth || !eth.request) return;

  const original = eth.request.bind(eth);

  eth.request = async (args) => {
    try {
      // args: { method, params }
      window.postMessage(
        {
          __W3RG__: true,
          payload: {
            ts: Date.now(),
            origin: location.origin,
            href: location.href,
            method: args?.method,
            params: args?.params ?? []
          }
        },
        "*"
      );
    } catch (e) {}

    return original(args);
  };
})();
