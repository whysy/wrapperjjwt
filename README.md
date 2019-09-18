# wrapperjjwt
Java wrapper for jjwt

# Ghost JWT wrapper

For a migration project from Wordpress to Ghost CMS, I needed to migrate all my articles (several thousand) to Ghost .

I have not found a Java implementation to generate tokens for Ghost so I created a very very simple one, it can be used for other people.

The Ghost Admin API is accessible through authentication by JWT token.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Installing

A step by step series of examples that tell you how to get a development env running

Clone the repository

```
git clone https://github.com/whysy/wrapperjjwt.git
```

Open the project and build

```
mvn clean install
```

Integration example

Add dependency to your pom.xml

```
<dependency>
    <groupId>whysy.wrapperjjwt</groupId>
    <artifactId>wrapperjjwt</artifactId>
    <version>1.0.0</version>
</dependency>
```

and use it

```
 String token = JWTWrapper.generateToken(API_KEY_VALUE);
```

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management

## Authors

* *Initial work* - [whysy](https://github.com/whysy)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details