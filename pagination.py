def paginateMongoQuery(querySet, per_page=10, page_number=1, order_by=None):
    offset = (page_number - 1) * per_page
    return querySet.skip(offset).limit(per_page).order_by(order_by).all()
