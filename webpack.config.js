const path = require('path');
const MonacoWebpackPlugin = require('monaco-editor-webpack-plugin');

module.exports = [
  {
    mode: 'development',
    entry: './src/renderer/index.tsx',
    target: 'electron-renderer',
    devtool: 'source-map',
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
        {
          test: /\.css$/,
          use: ['style-loader', 'css-loader'],
        },
        {
          test: /\.svg$/,
          type: 'asset/resource',
        },
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
    },
    plugins: [
      // Ensures Monaco workers/assets are bundled correctly for Electron
      new MonacoWebpackPlugin({
        languages: ['javascript', 'typescript', 'json', 'html', 'css'],
      }),
    ],
    output: {
      filename: 'renderer.js',
      path: path.resolve(__dirname, 'dist/renderer'),
    },
  },
  {
    mode: 'development',
    entry: './src/preload/preload.ts',
    target: 'electron-preload',
    devtool: 'source-map',
    module: {
      rules: [
        {
          test: /\.ts$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
      ],
    },
    resolve: {
      extensions: ['.ts', '.js'],
    },
    output: {
      filename: 'preload.js',
      path: path.resolve(__dirname, 'dist/preload'),
    },
  },
];

