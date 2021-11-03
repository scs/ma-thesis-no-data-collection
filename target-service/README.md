# Target-service
This is the target-service, where the implementation is tested on. The target-service is a simple PHP web-application, based on the laravel framework. [Docker-compose](https://docs.docker.com/compose/install/) is used for local deployment.

## local installation

To run the target-service, just start the containers with:

```
docker-compose up
```

As soon as the output has calmed down (several lines with `target-service-npm` and `[emitted]`) one can access the local instance under <http://localhost> and the database-tool (phpMyAdmin) under <http://localhost:8081>.


### laravel specific commands (artisan), composer, etc. in the container

As everything just works in the container (PHP, composer, artisan, etc.) one has to make calls like this:

```
docker exec -it target-service-app [composer|php|php artisan|etc] [command] 
docker exec -it target-service-npm [npm] [command] 
```
