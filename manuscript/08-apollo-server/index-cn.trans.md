> ## Apollo Server: Authentication

## Apollo Server: 认证

> Authentication in GraphQL is a popular topic. There is no opinionated way of doing it, but many people need it for their applications. GraphQL itself isn't opinionated about authentication since it is only a query language. If you want authentication in GraphQL, consider using GraphQL mutations. In this section, we use a minimalistic approach to add authentication to your GraphQL server. Afterward, it should be possible to register (sign up) and login (sign in) a user to your application. The previously used `me` user will be the authenticated user.

在 GraphQL 中认证是一个很热门的话题。没有固定的方法去做认证，但大多数人的应用都需要认证。GraphQL 本身并没有固定的认证机制，因为它只是一种查询语言。如果你想要在 GraphQL 中实现认证，考虑用 GraphQL 变更（操作）。在这一部分中，我们用最简化的方法去给你的 GraphQL 服务器添加认证。之后，应该可以通过服务器注册和登录一个用户到你的应用。之前用过的`me`用户将会做为一个认证过的用户。

>In preparation for the authentication mechanism with GraphQL, extend the user model in the _src/models/user.js_ file. The user needs an email address (as unique identifier) and a password. Both email address and username (another unique identifier) can be used to sign in to the application, which is why both properties were used for the user's `findByLogin()` method.

在准备用 GraphQL 实现认证机制时，在_src/models/user.js_文件中扩展用户模型。用户需要一个电子邮件地址（作为唯一标识符）和一个密码。电子邮件地址和用户名（另一种唯一标识符）都可以被用于登录到应用，这就是为什么这两个属性都被用于用户的`findByLogin()`方法。

{title="src/models/user.js",lang="javascript"}

```
...

const user = (sequelize, DataTypes) => {
  const User = sequelize.define('user', {
    username: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
      validate: {
        notEmpty: true,
      },
    },
# leanpub-start-insert
    email: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
      validate: {
        notEmpty: true,
        isEmail: true,
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
        len: [7, 42],
      },
    },
# leanpub-end-insert
  });

  ...

  return User;
};

export default user;
```

>The two new entries for the user model have their own validation rules, same as before. The password of a user should be between 7 and 42 characters, and the email should have a valid email format. If any of these validations fails during user creation, it generates a JavaScript error, transforms and transfers the error with GraphQL. The registration form in the client application could display the validation error then.

同以前一样，用户模型的两个新字段拥有自己的验证规则。用户密码应该是 7 到 42 位的字符串，并且电子邮件应该具有合法的电子邮件格式。如果在用户创建期间任何一个验证失败了，则会生成一个 JavaScript 错误，并用GraphQL转换和传输错误。在客户端应用程序中的注册表单可能会显示验证错误。

>You may want to add the email, but not the password, to your GraphQL user schema in the _src/schema/user.js_ file too:

你也可能想添加电子邮件而不是密码到文件_src/schema/user.js_中的 GraphQL 用户模型:

{title="src/schema/user.js",lang="javascript"}

```
import { gql } from 'apollo-server-express';

export default gql`
  ...

  type User {
    id: ID!
    username: String!
# leanpub-start-insert
    email: String!
# leanpub-end-insert
    messages: [Message!]
  }
`;
```

Next, add the new properties to your seed data in the _src/index.js_ file:

然后，添加新的属性到文件`src/index.js`中的种子数据：

{title="src/index.js",lang="javascript"}

```
const createUsersWithMessages = async () => {
  await models.User.create(
    {
      username: 'rwieruch',
# leanpub-start-insert
      email: 'hello@robin.com',
      password: 'rwieruch',
# leanpub-end-insert
      messages: [ ... ],
    },
    {
      include: [models.Message],
    },
  );

  await models.User.create(
    {
      username: 'ddavids',
# leanpub-start-insert
      email: 'hello@david.com',
      password: 'ddavids',
# leanpub-end-insert
      messages: [ ... ],
    },
    {
      include: [models.Message],
    },
  );
};
```

That's the data migration of your database to get started with GraphQL authentication.

这就是数据库的数据迁移以便开始 GraphQL 认证

### Registration (Sign Up) with GraphQL

### 用 GraphQL 实现注册

>Now, let's examine the details for GraphQL authentication. You will implement two GraphQL mutations: one to register a user, and one to log in to the application. Let's start with the sign up mutation in the _src/schema/user.js_ file:

现在，让我们来考察 GraphQL 认证的具体细节。你将会实现两个 GraphQL 变更（操作）：一个用于注册用户，另一个用于登录到应用程序。让我们从_src/schema/user.js_ 文件中的注册开始：

{title="src/schema/user.js",lang="javascript"}

```
import { gql } from 'apollo-server-express';

export default gql`
  extend type Query {
    users: [User!]
    user(id: ID!): User
    me: User
  }

# leanpub-start-insert
  extend type Mutation {
    signUp(
      username: String!
      email: String!
      password: String!
    ): Token!
  }
# leanpub-end-insert

# leanpub-start-insert
  type Token {
    token: String!
  }
# leanpub-end-insert

  type User {
    id: ID!
    username: String!
    messages: [Message!]
  }
`;
```

The `signUp` mutation takes three non-nullable arguments: username, email, and password. These are used to create a user in the database. The user should be able to take the username or email address combined with the password to enable a successful login.

这个`signUP` mutation 需要 3 个不为空的参数：用户名，邮箱和密码。这些参数是用来在数据库中创建用户。这个用户应该被允许用用户名或者邮箱组合密码成功登录。

Now we'll consider the return type of the `signUp` mutation. Since we are going to use a token-based authentication with GraphQL, it is sufficient to return a token that is nothing more than a string. However, to distinguish the token in the GraphQL schema, it has its own GraphQL type. You will learn more about tokens in the following, because the token is all about the authentication mechanism for this application.

现在我们将会考虑`signUp` mutation 的返回值类型。因为我们准备用基于 GraphQL 的 token-based 认证。只返回一个 token 是非常高效的，没有什么比返回一个字符串更高效的了。然而，为了在 GraphQL schema 中区分 token，它将用后自己的 GraphQL 类型。你讲会在接下来学习到更多关于 token 的，因为这个应用所有关于认证的机制都是 token。

First, add the counterpart for your new mutation in the GraphQL schema as a resolver function. In your _src/resolvers/user.js_ file, add the following resolver function that creates a user in the database and returns an object with the token value as string.

首先，复制一份新的 mutation 在 GraphQL schema 做为一个 resolver function。在你的`_src/resolvers/user.js` 文件中，添加如下 resolver function 用于在数据库中创建一个用户并且返回一个对象包含对应的字符串 token。

{title="src/resolvers/user.js",lang="javascript"}

```
# leanpub-start-insert
const createToken = async (user) => {
  ...
};
# leanpub-end-insert

export default {
  Query: {
    ...
  },

# leanpub-start-insert
  Mutation: {
    signUp: async (
      parent,
      { username, email, password },
      { models },
    ) => {
      const user = await models.User.create({
        username,
        email,
        password,
      });

      return { token: createToken(user) };
    },
  },
# leanpub-end-insert

  ...
};
```

That's the GraphQL framework around a token-based registration. You created a GraphQL mutation and resolver for it, which creates a user in the database based on certain validations and its incoming resolver arguments. It creates a token for the registered user. For now, the set up is sufficient to create a new user with a GraphQL mutation.

那就是 GraphQL 框架关于如何创建一个 token-based 的注册。你为注册创建一个 GraphQL mutation 和 一个 resolver，在数据库创建一个用户基于某些验证和它即将到来的 resolver 参数。它将会为注册的用户创建一个 token。目前，这个 set up 例子是非常高效的去创建一个用户用 GraphQL mutation。

### Securing Passwords with Bcrypt

### 用 Bcrypt 加密密码

There is one major security flaw in this code: the user password is stored in plain text in the database, which makes it much easier for third parties to access it. To remedy this, we use add-ons like [bcrypt](https://github.com/kelektiv/node.bcrypt.js) to hash passwords. First, install it on the command line:

这段代码中有一点安全的漏洞：用户密码是直接以文本形式存储在数据库中，这样会让第三方很容易的获取密码。为了弥补这一点，我们用 加密库 像 [bcrypt](https://github.com/kelektiv/node.bcrypt.js) 去加密密码。首先，通过命令行将其安装。

{title="Command Line",lang="json"}

```
npm install bcrypt --save
```

Note: If you run into any problems with bcrypt on Windows while installing it, you can try out a substitute called [bcrypt.js](https://github.com/dcodeIO/bcrypt.js). It is slower, but people reported that it works on their machine.

注意：如果你在 Windows 上安装 bcrypt 的过程中出现任何问题，你可以尝试用代替方案[bcrypt.js](https://github.com/dcodeIO/bcrypt.js)。它有点满，但是有人说他们在他的机器上尝试成功过。

Now it is possible to hash the password with bcrypt in the user's resolver function when it gets created on a `signUp` mutation. There is also an alternative way with Sequelize. In your user model, define a hook function that is executed every time a user entity is created:

现在可以用 bcrypt 在用户 resolver 方法中加密密码当用户被`signUp`mutation 创建的时候。还有一种代替的方法是通过 Sequelize。在你的用户模型中，定义一个回调方法每当用户创建的时候就被调用。

{title="src/models/user.js",lang="javascript"}

```
const user = (sequelize, DataTypes) => {
  const User = sequelize.define('user', {
    ...
  });

  ...

# leanpub-start-insert
  User.beforeCreate(user => {
    ...
  });
# leanpub-end-insert

  return User;
};

export default user;
```

In this hook function, add the functionalities to alter your user entity's properties before they reach the database. Let's do it for the hashed password by using bcrypt.

在这个回调方法中，添加在被存储到数据库前修改用户实例属性的功能。让我们为了用 bcrypt 加密的密码添加这个功能。

{title="src/models/user.js",lang="javascript"}

```
# leanpub-start-insert
import bcrypt from 'bcrypt';
# leanpub-end-insert

const user = (sequelize, DataTypes) => {
  const User = sequelize.define('user', {
    ...
  });

  ...

# leanpub-start-insert
  User.beforeCreate(async user => {
    user.password = await user.generatePasswordHash();
  });
# leanpub-end-insert

# leanpub-start-insert
  User.prototype.generatePasswordHash = async function() {
    const saltRounds = 10;
    return await bcrypt.hash(this.password, saltRounds);
  };
# leanpub-end-insert

  return User;
};

export default user;
```

The bcrypt `hash()` method takes a string--the user's password--and an integer called salt rounds. Each salt round makes it more costly to hash the password, which makes it more costly for attackers to decrypt the hash value. A common value for salt rounds nowadays ranged from 10 to 12, as increasing the number of salt rounds might cause performance issues both ways.

bcrypt 的`hash()`方法需要一个字符串--用户密码和一个整数叫盐轮。每个盐轮让密码密码变得更代价高昂，同时也让攻击者解密加密的值变得更昂贵。现在通常盐轮的范围是 10 到 12，因为增加盐轮的范围将会同时增加加密和解密的难度。

In this implementation, the `generatePasswordHash()` function is added to the user's prototype chain. That's why it is possible to execute the function as method on each user instance, so you have the user itself available within the method as `this`. You can also take the user instance with its password as an argument, which I prefer, though using JavaScript's prototypal inheritance a good tool for any web developer. For now, the password is hashed with bcrypt before it gets stored every time a user is created in the database,.

这个视线中，`generatePasswordHash()` 方法被添加到用户的原型链中。这就是为什么我们可以在每一个用户的事例中执行这个方法，所以你可以通过`this`在这个方法中访问到这个用户。你也可以把用户实例和其密码做为参数，我更喜欢，通过运用 JavaScript 的原型链继承一个好的工具为了任何一个开发者。现在，每一个用户在数据库中被创建的时候都是通过 bcrypt 加密密码的。

### Token based Authentication in GraphQL

### 在 GraphQL 中基于 Token 的认证

We still need to implement the token based authentication. So far, there is only a placeholder in your application for creating the token that is returned on a sign up and sign in mutation. A signed in user can be identified with this token, and is allowed to read and write data from the database. Since a registration will automatically lead to a login, the token is generated in both phases.

我们仍然需要实现基于 token 的认证。目前为止，在你的应用中只有一个占位符去创建一个被注册和登录 mutation 返回的 token。一个登录的用户可以被这个 token 认证，同时拥有数据库数据读写权限。因为用户注册后会自动登录，token 会同时被生成。

Next are the implementation details for the token-based authentication in GraphQL. Regardless of GraphQL, you are going to use a [JSON web token (JWT)](https://jwt.io/) to identify your user. The definition for a JWT from the official website says: _JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties._ In other words, a JWT is a secure way to handle the communication between two parties (e.g. a client and a server application). If you haven't worked on security related applications before, the following section will guide you through the process, and you'll see the token is just a secured JavaScript object with user information.

下一步是在 GraphQL 中基于 token 认证的实现细节。不考虑 GraphQL，你将会用[JSON web token (JWT)](https://jwt.io/)去鉴定你的用户。JWT 官方网站给出的定义说：_JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties._ 换句话说，JWT 是一种处理两端通信的安全方法（例如 客户端和服务端）。如果你之前没有在安全相关的应用上工作过，接下来的部分将会引导你熟悉它，同时你也会明白 token 就是一种加过密的 JavaScript 用户信息对象。

To create JWT in this application, we'll use the popular [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) node package. Install it on the command line:

为了在这个应用中创建 JWT，你将会用流行的[jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)node 包。在命令行中将其安装。

{title="Command Line",lang="json"}

```
npm install jsonwebtoken --save
```

Now, import it in your _src/resolvers/user.js_ file and use it to create the token:

现在，将其倒入到`_src/resolvers/user.js_`文件并用它创建 token：

{title="src/resolvers/user.js",lang="javascript"}

```
# leanpub-start-insert
import jwt from 'jsonwebtoken';
# leanpub-end-insert

const createToken = async user => {
# leanpub-start-insert
  const { id, email, username } = user;
  return await jwt.sign({ id, email, username });
# leanpub-end-insert
};

...
```

The first argument to "sign" a token can be any user information except sensitive data like passwords, because the token will land on the client side of your application stack. Signing a token means putting data into it, which you've done, and securing it, which you haven't done yet. To secure your token, pass in a secret (**any** long string) that is **only available to you and your server**. No third-party entities should have access, because it is used to encode (sign) and decode your token.

第一个去“签署”一个 token 的参数可以是任何用户的信息除了敏感的信息例如密码，因为 token 将会被客户端获取。签署一个 token 意味着放置数据到其里面，这个你已经做了，和将其加密，这个你还没有做。为了保护你的 token，传入一个密钥（**angy** 长字符串）**只能被你和你的服务器用**。不能被第三方的入口获取到密码，因为这个密钥将会被用来加密（签署）和解密你的 token。

Add the secret to your environment variables in the _.env_ file:

添加密钥到你的环境变量，在*.env* 文件：

{title=".env",lang="javascript"}

```
DATABASE=postgres
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres

# leanpub-start-insert
SECRET=wr3r23fwfwefwekwself.2456342.dawqdq
# leanpub-end-insert
```

Then, in the _src/index.js_ file, pass the secret via Apollo Server's context to all resolver functions:

然后，在文件*src/index.js*，通过 Apollo 服务器的上下文传入密钥到所有的 resolver 方法：

{title="src/index.js",lang="javascript"}

```
const server = new ApolloServer({
  typeDefs: schema,
  resolvers,
  ...
  context: async () => ({
    models,
    me: await models.User.findByLogin('rwieruch'),
# leanpub-start-insert
    secret: process.env.SECRET,
# leanpub-end-insert
  }),
});
```

Next, use it in your `signUp` resolver function by passing it to the token creation. The `sign` method of JWT handles the rest. You can also pass in a third argument for setting an expiration time or date for a token. In this case, the token is only valid for 30 minutes, after which a user has to sign in again.

下一步，通过将其传入到 token 创建方法在`signUp` resolver 方法中运用。JWT 的`sign`方法处理其他的。你也可以为了 token 传入第三个参数去设置过期时间或者日期。在这个例子中，token 只有 30 分钟的合法时间，如果过了合法时间，用户只能再次登录。

{title="src/resolvers/user.js",lang="javascript"}

```
# leanpub-start-insert
import jwt from 'jsonwebtoken';
# leanpub-end-insert

# leanpub-start-insert
const createToken = async (user, secret, expiresIn) => {
# leanpub-end-insert
  const { id, email, username } = user;
# leanpub-start-insert
  return await jwt.sign({ id, email, username }, secret, {
    expiresIn,
  });
# leanpub-end-insert
};

export default {
  Query: {
    ...
  },

  Mutation: {
    signUp: async (
      parent,
      { username, email, password },
# leanpub-start-insert
      { models, secret },
# leanpub-end-insert
    ) => {
      const user = await models.User.create({
        username,
        email,
        password,
      });

# leanpub-start-insert
      return { token: createToken(user, secret, '30m') };
# leanpub-end-insert
    },
  },

  ...
};
```

Now you have secured your information in the token as well. If you would want to decode it, in order to access the secured data (the first argument of the `sign` method), you would need the secret again. Furthermore, the token is only valid for 30 minutes.

现在你也将你的信息保护在 token 中了。如果你想解密它，为了获取保护的数据（`sign`方法的第一个参数），你还需要这个密钥。此外，这个 token 的合法时间只有三十分钟。

That's it for the registration: you are creating a user and returning a valid token that can be used from the client application to authenticate the user. The server can decode the token that comes with every request and allows the user to access sensitive data. You can try out the registration with GraphQL Playground, which should create a user in the database and return a token for it. Also, you can check your database with `psql` to test if the use was created and with a hashed password.

这就是注册：你创建了一个用户并返回一个合法的 token，可以被用户应用用于认证用户。服务器可以解密每一个从请求过来的 token 并允许用户访问敏感的数据。你可以通过 GraphQL Playground 试练注册，这个应该可以在数据库中创建一个用户并返回一个 token。同样的，你可以通过`psql`检查你的数据库判断用户是否被创建并且包含一个加密的密码。

### Login (Sign In) with GraphQL

### 用 GraphQL 登录（Sign In）

Before you dive into the authorization with the token on a per-request basis, let's implement the second mutation for the authentication mechanism: the `signIn` mutation (or login mutation). Again, first we add the GraphQL mutation to your user's schema in the _src/schema/user.js_ file:

在你深入基于每个请求的 token 认证之前，让我们实现第二个 mutation 为了认证机制：`signIn` mutation（或者登录 mutation）。再一次，首先我们添加 GraphQL mutation 到你用户的 schema，在*src/schema/user.js*文件：

{title="src/schema/user.js",lang="javascript"}

```
import { gql } from 'apollo-server-express';

export default gql`
  ...

  extend type Mutation {
    signUp(
      username: String!
      email: String!
      password: String!
    ): Token!

# leanpub-start-insert
    signIn(login: String!, password: String!): Token!
# leanpub-end-insert
  }

  type Token {
    token: String!
  }

  ...
`;
```

Second, add the resolver counterpart to your _src/resolvers/user.js_ file:

然后，添加 resolver 副本到你的*src/resolvers/user.js* 文件：

{title="src/resolvers/user.js",lang="javascript"}

```
import jwt from 'jsonwebtoken';
# leanpub-start-insert
import { AuthenticationError, UserInputError } from 'apollo-server';
# leanpub-end-insert

...

export default {
  Query: {
    ...
  },

  Mutation: {
    signUp: async (...) => {
      ...
    },

# leanpub-start-insert
    signIn: async (
      parent,
      { login, password },
      { models, secret },
    ) => {
      const user = await models.User.findByLogin(login);

      if (!user) {
        throw new UserInputError(
          'No user found with this login credentials.',
        );
      }

      const isValid = await user.validatePassword(password);

      if (!isValid) {
        throw new AuthenticationError('Invalid password.');
      }

      return { token: createToken(user, secret, '30m') };
    },
# leanpub-end-insert
  },

  ...
};
```

Let's go through the new resolver function for the login step by step. As arguments, the resolver has access to the input arguments from the GraphQL mutation (login, password) and the context (models, secret). When a user tries to sign in to your application, the login, which can be either the unique username or unique email, is taken to retrieve a user from the database. If there is no user, the application throws an error that can be used in the client application to notify the user. If there is an user, the user's password is validated. You will see this method on the user model in the next example. If the password is not valid, the application throws an error to the client application. If the password is valid, the `signIn` mutation returns a token identical to the `signUp` mutation. The client application either performs a successful login or shows an error message for invalid credentials. You can also see specific Apollo Server Errors used over generic JavaScript Error classes.

让我们一步一步检查新的登录 resolver 方法。作为一个参数，resolver 拥有从 GraphQL mutation（login，password）输入参数和上下文（models，secret）获取输入参数的权限。当一个用户尝试登录到你的应用，登录，可以是不相同的用户名或者是邮箱，将会被用于从数据库中获取用户。如果没有该用户，应用将会抛出一个错误用于客户端提示用户。如果用户存在，用户的密码将会被验证。你将会在下一个例子的用户模型中看到这个方法。如果密码不合法，应用抛出一个错误给客户端。如果密码合法，`signIn`mutation 返回一个同`signUp`mutaton 一样的 token。客户端应用要么登录成功要么给不合法的密钥显示一个错误信息。你也可以看到特殊的 Apollo Server Errors 对应普通的 JavaScript Error 类。

Next, we want to implement the `validatePassword()` method on the user instance. Place it in the _src/models/user.js_ file, because that's where all the model methods for the user are stored, same as the `findByLogin()` method.

下一步，我们想去实现在用户实例中的`validatePassword()` 方法。将其放置在*src/models/user.js* 文件中，因为所有用户模式方法存储的地方，同`findByLogin()`方法一样。

{title="src/models/user.js",lang="javascript"}

```
import bcrypt from 'bcrypt';

const user = (sequelize, DataTypes) => {
  ...

  User.findByLogin = async login => {
    let user = await User.findOne({
      where: { username: login },
    });

    if (!user) {
      user = await User.findOne({
        where: { email: login },
      });
    }

    return user;
  };

  User.beforeCreate(async user => {
    user.password = await user.generatePasswordHash();
  });

  User.prototype.generatePasswordHash = async function() {
    const saltRounds = 10;
    return await bcrypt.hash(this.password, saltRounds);
  };

# leanpub-start-insert
  User.prototype.validatePassword = async function(password) {
    return await bcrypt.compare(password, this.password);
  };
# leanpub-end-insert

  return User;
};

export default user;
```

Again, it's a prototypical JavaScript inheritance for making a method available in the user instance. In this method, the user (this) and its password can be compared with the incoming password from the GraphQL mutation using bcrypt, because the password on the user is hashed, and the incoming password is plain text. Fortunately, bcrypt will tell you whether the password is correct or not when a user signs in.

再一次，这是 JavaScript 的原型继承让一个方法可以在用户实例上可用。在这个方法中，用户（this）和其密码可以和到来的密码一起用 bcrypt 从 GraphQL mutation 比较。因为用户的密码是加过密的，到来的密码是普通文本。幸运的是，在登录的时候，bcrypt 将会告诉你密码是否是正确的。

Now you have set up registration (sign up) and login (sign in) for your GraphQL server application. You used bcrypt to hash and compare a plain text password before it reaches the database with a Sequelize hook function, and you used JWT to encrypt user data with a secret to a token. Then the token is returned on every sign up and sign in. Then the client application can save the token (e.g. local storage of the browser) and send it along with every GraphQL query and mutation as authorization.

现在你已经给你的 GraphQL 服务器应用设置好了注册（sign up）和登录（sign in）。你在从数据库获取之前用 bcrypt 去加密和比较普通密码通过一个勾子方法，同时你通过 JWT 用一个密钥去加密用户数据到一个 token。然后这个 token 被返回给每次注册或者登录。然后客户端可以保存 token（例如 浏览器本地存储）并随同每一个 GraphQL 请求和 mutation 一起发送做为认证。

The next section will teach you about authorization in GraphQL on the server-side, and what should you do with the token once a user is authenticated with your application after a successful registration or login.

接下来的部分将会教你关于在服务器端用 GraphQL 授权，和成功注册或者登录过后，当用户得到应用的认证过后，可以用 token 做什么。

### Exercises:

### 练习：

- Confirm your [source code for the last section](https://github.com/the-road-to-graphql/fullstack-apollo-react-express-boilerplate-project/tree/831ab566f0b5c5530d9270a49936d102f7fdf73c)
- Register (sign up) a new user with GraphQL Playground
- Check your users and their hashed passwords in the database with `psql`
- Read more about [JSON web tokens (JWT)](https://jwt.io/)
- Login (sign in) a user with GraphQL Playground
  - copy and paste the token to the interactive token decoding on the JWT website (conclusion: the information itself isn't secure, that's why you shouldn't put a password in the token)

* 确认你的[上一节的源代码](https://github.com/the-road-to-graphql/fullstack-apollo-react-express-boilerplate-project/tree/831ab566f0b5c5530d9270a49936d102f7fdf73c)
* 用 GraphQL Playground 注册（sign up）一个新用户
* 用`psql`在数据库中检查你的用户和其加密的密码
* 了解更多关于[JSON 网站 tokens (JWT)](https://jwt.io/)
* 用 GraphQL Playground 登录（sign in）一个用户
  - 复制和粘贴 token 到交互式的 token 解密在 JWT 网上（总结：信息本身并没有被保护，这就是为什么你不能将你的密码放在你的 token 中）
