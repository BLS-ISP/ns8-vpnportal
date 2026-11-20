const path = require("path");
const { defineConfig } = require("@vue/cli-service");

module.exports = defineConfig({
  publicPath: "./",
  productionSourceMap: false,
  configureWebpack: {
    performance: {
      hints: false,
    },
    ignoreWarnings: [
      /export 'default' \(imported as 'style\d+'\) was not found/,
    ],
    resolve: {
      alias: {
        crypto: path.resolve(__dirname, "src/shims/crypto.js"),
      },
    },
  },
  css: {
    loaderOptions: {
      sass: {
        sassOptions: {
          quietDeps: true,
        },
      },
    },
  },
  chainWebpack: (config) => {
    config.optimization.delete("splitChunks");
  },
});
