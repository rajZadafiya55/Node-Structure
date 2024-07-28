# Steps to Set Up and Run the Node.js Application

1. **Update `package.json`**

   - Open the `package.json` file.
   - Add or change the `"type"` field to `"module"`.

   ```json
   {
     "type": "module"
   }
   ```

2. **Copy `index.js` from `nodeModules` Directory**

   - Go to the `nodeModules` directory.
   - Copy the `index.js` file.

3. **Paste `index.js` in Root Directory**

   - Paste the copied `index.js` file into the root directory of your project.

4. **Run the Application**

   - Open your terminal.
   - Navigate to the root directory of your project.
   - Run the following command to generate the application folder:

   ```sh
   node index.js
   ```

### Directory Structure

```
src
├── app.js
├── controllers
│ └── user.controller.js
├── db
│ └── index.js
├── index.js
├── middlewares
│ ├── auth.middleware.js
│ └── multer.middleware.js
├── models
│ └── user.model.js
├── routes
│ └── user.route.js
└── utils
├── ApiError.js
├── ApiRespone.js
├── asyncHandler.js
└── cloudinary.js


```