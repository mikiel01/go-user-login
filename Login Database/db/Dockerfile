FROM postgres
Run echo 'Db Docker'
ENV POSTGRES_PASSWORD myPassword
ENV POSTGRES_DB arrayDB
ADD ./Users_Table.sql /docker-entrypoint-initdb.d/


EXPOSE 5432
