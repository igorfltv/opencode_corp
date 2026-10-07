// @bun
// src/tui.js
var tui_default = {
  id: "company-corporate-ui",
  setup(context) {
    return context.data.listen(({ details }) => {
      if (details.type !== "rpc.company.corporate.notice")
        return;
      const location = context.location ?? context.data.location.default();
      if (details.location?.directory !== location.directory)
        return;
      const { message, level } = details.data;
      context.ui.toast.show({ title: "Company OpenCode", message, variant: level, duration: 7000 });
    });
  }
};
export {
  tui_default as default
};
