function doGet(e) {
  let html;

  if (!e.parameter.page) {
    html = HtmlService.createTemplateFromFile('index').evaluate();
  }
  else {
    html = HtmlService.createTemplateFromFile(e.parameter['page']).evaluate();
  }

  html.addMetaTag('viewport', 'width=device-width, initial-scale=1');
  return html;
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename)
      .getContent();
}

function getScriptUrl() {
    var url = ScriptApp.getService().getUrl();
    return url;
}

